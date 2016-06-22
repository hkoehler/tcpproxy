/***** added by SmApper Inc. - hfk *****/

/*
 * write sk_buff to TCP socket
 */
static int tcp_send_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mss_now, size_goal, sent;

	mss_now = tcp_send_mss(sk, &size_goal, 0);

	/* 
	 * initialize TCP sk_buff control buffer 
	 * enqueue sk_buff to sk 
	 */
	skb_entail(sk, skb);
	sent = skb->len;

	if (!sk_wmem_schedule(sk, skb->len)) 
		return -ENOMEM;

	/* can we use HW checksum? */
	if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
		skb->ip_summed = CHECKSUM_PARTIAL;
	else
		skb->ip_summed = CHECKSUM_NONE;
	tp->write_seq += skb->len;
	TCP_SKB_CB(skb)->end_seq += skb->len;
	skb_shinfo(skb)->gso_segs = 0;

	if (skb->len < size_goal)
		return sent;
	
	/* should this ever execute, now that we forward single TCP segments? */
	//printk(KERN_INFO "size goal >= skb len\n");
	if (forced_push(tp)) {
		tcp_mark_push(tp, skb);
		__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
	}
	else if (skb == tcp_send_head(sk))
		tcp_push_one(sk, mss_now);

	return sent;
}

/*
 * write sk_buff queue to TCP socket
 */
int tcp_send_skb_queue(struct sock *sk, struct sk_buff_head *queue)
{
	struct tcp_sock *tp;
	int mss_now, size_goal;
	struct sk_buff *skb;
	int res, sent = 0;

	if (skb_queue_empty(queue))
		return 0;

	lock_sock(sk);
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
	mss_now = tcp_send_mss(sk, &size_goal, 0);

	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN)) {
		res = -EPIPE;
		goto out;
	}

	if (!(sk->sk_route_caps & NETIF_F_SG))
		printk(KERN_INFO "route doesn't support scatter/gather I/O\n");

	while ((skb = skb_dequeue(queue))) {
		//printk(KERN_INFO "%s: skb=%p, nohdr=%d\n", __func__, skb, skb->nohdr);
		res = tcp_send_skb(sk, skb);
		if (res < 0)
			goto out;
		sent += res;
	}

	tp = tcp_sk(sk);
	tcp_push(sk, 0, mss_now, tp->nonagle);

out:
	release_sock(sk);
	return sent;
}
EXPORT_SYMBOL(tcp_send_skb_queue);

/*
 * read TCP segments into sk_buff queue
 */
int tcp_recv_skb_queue(struct sock *sk, struct sk_buff_head *queue)
{
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int received = 0;
	u32 offset;
	
	lock_sock(sk);
	tp = tcp_sk(sk);

	if (sk->sk_state == TCP_LISTEN) {
		received = -ENOTCONN;
		goto out;
	}
	
	while ((skb = tcp_recv_skb(sk, tp->copied_seq, &offset))) {
		int free_skb = false;
		tp->copied_seq += skb->len;
		received += skb->len;

		/*printk(KERN_DEBUG "skb: len=%d data len %d truesize=%d\n", 
			skb->len, skb->data_len, skb->truesize);
		printk(KERN_DEBUG "skb_shinfo(skb): nr_frags=%d\n", 
			skb_shinfo(skb)->nr_frags);*/

		/* remove skb from receive queue */
		__skb_unlink(skb, &sk->sk_receive_queue);

		/* drop reference to routing entry */
		skb_dst_drop(skb);
		/*
		 * call destructor manually as skb not freed
		 * TCP window sizing depends on it
		 */
		skb_orphan(skb);
		
		if (skb_has_frags(skb)) {
			struct sk_buff *newskb, *frag;

			/* 
			 * forward each fragment separately
			 * tcp_push() can't handle with fragmented sk_buffs!
			 */
			skb_walk_frags (skb, frag) {
				/* printk(KERN_DEBUG "skb iter: len=%d data len %d truesize=%d\n", 
				iter->len, iter->data_len, iter->truesize); */
				newskb = skb_clone(frag, GFP_ATOMIC);
				if (newskb == NULL) {
					received = -ENOMEM;
					kfree_skb(skb);
					goto out;
				}
				skb_queue_tail(queue, newskb);
			}
			free_skb = true;
		}
		else
			skb_queue_tail(queue, skb);

		if (tcp_hdr(skb)->fin) {
			printk(KERN_INFO "FIN received on %p\n", sk);
			tp->copied_seq++;
			if (free_skb)
				kfree_skb(skb);
			break;
		}
		if (free_skb)
			kfree_skb(skb);
	}

	/* XXX not need on FIN */
	/* adjust TCP window clamp from tp->copied_seq */
	tcp_rcv_space_adjust(sk);
	/* generate ACK frame for sake of window update */
	tcp_cleanup_rbuf(sk, received);

out:
	release_sock(sk);
	return received;
}
EXPORT_SYMBOL(tcp_recv_skb_queue);

