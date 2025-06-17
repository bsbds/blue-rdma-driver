// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#ifndef __BLUERDMA_VERBS_H__
#define __BLUERDMA_VERBS_H__

#include <rdma/ib_verbs.h>

#pragma region mandatory methods

int bluerdma_query_device(struct ib_device *ibdev, struct ib_device_attr *attr,
			  struct ib_udata *udata);
int bluerdma_query_port(struct ib_device *ibdev, u32 port_num,
			struct ib_port_attr *attr);

int bluerdma_alloc_pd(struct ib_pd *pd, struct ib_udata *udata);
int bluerdma_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata);

int bluerdma_create_qp(struct ib_qp *qp, struct ib_qp_init_attr *init_attr,
		       struct ib_udata *udata);
int bluerdma_destroy_qp(struct ib_qp *qp, struct ib_udata *udata);
int bluerdma_modify_qp(struct ib_qp *qp, struct ib_qp_attr *attr, int attr_mask,
		       struct ib_udata *udata);

int bluerdma_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		       const struct ib_send_wr **bad_wr);
int bluerdma_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		       const struct ib_recv_wr **bad_wr);

int bluerdma_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
		       struct ib_udata *udata);
int bluerdma_destroy_cq(struct ib_cq *cq, struct ib_udata *udata);
int bluerdma_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);

int bluerdma_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);

struct ib_mr *bluerdma_get_dma_mr(struct ib_pd *ibpd, int access);
struct ib_mr *bluerdma_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				   u64 virt_addr, int access_flags,
				   struct ib_udata *udata);
int bluerdma_dereg_mr(struct ib_mr *mr, struct ib_udata *udata);

int bluerdma_get_port_immutable(struct ib_device *ibdev, u32 port_num,
				struct ib_port_immutable *immutable);

#pragma endregion mandatory methods

int bluerdma_alloc_ucontext(struct ib_ucontext *ibuc, struct ib_udata *udata);
void bluerdma_dealloc_ucontext(struct ib_ucontext *ibuc);

int bluerdma_query_pkey(struct ib_device *ibdev, u32 port_num, u16 index,
			u16 *pkey);

int bluerdma_query_gid(struct ib_device *ibdev, u32 port_num, int index,
		       union ib_gid *gid);

int bluerdma_add_gid(const struct ib_gid_attr *attr, void **context);
int bluerdma_del_gid(const struct ib_gid_attr *attr, void **context);

#endif // __BLUERDMA_VERBS_H__
