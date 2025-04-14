// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <rdma/ib_mad.h>

#include "bluerdma.h"
#include "verbs.h"

int bluerdma_query_device(struct ib_device *ibdev, struct ib_device_attr *attr,
			  struct ib_udata *udata)
{
	pr_info("bluerdma_query_device\n");
	return 0;
}
int bluerdma_query_port(struct ib_device *ibdev, u32 port_num,
			struct ib_port_attr *attr)
{
	struct bluerdma_dev *dev = to_bdev(ibdev);
	// struct net_device *ndev = dev->netdev;

	memset(attr, 0, sizeof(*attr));

	attr->gid_tbl_len = 1;
	// attr->port_cap_flags = IB_PORT_CM_SUP | IB_PORT_DEVICE_MGMT_SUP;
	// attr->max_msg_sz = -1;

	// if (!ndev)
	// 	goto out;

	// ib_get_eth_speed(ibdev, port, &attr->active_speed, &attr->active_width);
	// attr->max_mtu = ib_mtu_int_to_enum(ndev->mtu);
	// attr->active_mtu = ib_mtu_int_to_enum(ndev->mtu);
	// if (netif_running(ndev) && netif_carrier_ok(ndev))
	dev->state = IB_PORT_ACTIVE;
	// else
	// 	dev->state = IB_PORT_DOWN;
	attr->state = dev->state;

	// out:
	if (dev->state == IB_PORT_ACTIVE)
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	else
		attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;

	return 0;
}

int bluerdma_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	pr_info("bluerdma_alloc_pd\n");
	return 0;
}
int bluerdma_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	pr_info("bluerdma_dealloc_pd\n");
	return 0;
}

int bluerdma_create_qp(struct ib_qp *qp, struct ib_qp_init_attr *init_attr,
		       struct ib_udata *udata)
{
	pr_info("bluerdma_create_qp\n");
	return 0;
}
int bluerdma_destroy_qp(struct ib_qp *qp, struct ib_udata *udata)
{
	pr_info("bluerdma_destroy_qp\n");
	return 0;
}
int bluerdma_modify_qp(struct ib_qp *qp, struct ib_qp_attr *attr, int attr_mask,
		       struct ib_udata *udata)
{
	pr_info("bluerdma_modify_qp\n");
	return 0;
}

int bluerdma_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		       const struct ib_send_wr **bad_wr)
{
	pr_info("bluerdma_post_send\n");
	return 0;
}
int bluerdma_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		       const struct ib_recv_wr **bad_wr)
{
	pr_info("bluerdma_post_recv\n");
	return 0;
}

int bluerdma_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
		       struct ib_udata *udata)
{
	pr_info("bluerdma_create_cq\n");
	return 0;
}
int bluerdma_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
{
	pr_info("bluerdma_destroy_cq\n");
	return 0;
}
int bluerdma_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	pr_info("bluerdma_poll_cq\n");
	return 0;
}

int bluerdma_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	pr_info("bluerdma_req_notify_cq\n");
	return 0;
}

struct ib_mr *bluerdma_get_dma_mr(struct ib_pd *ibpd, int access)
{
	struct ib_mr *mr;

	pr_info("bluerdma_get_dma_mr\n");

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	return mr;
}
struct ib_mr *bluerdma_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				   u64 virt_addr, int access_flags,
				   struct ib_udata *udata)
{
	struct ib_mr *mr;
	pr_info("bluerdma_reg_user_mr\n");

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	return mr;
}
int bluerdma_dereg_mr(struct ib_mr *mr, struct ib_udata *udata)
{
	pr_info("bluerdma_dereg_mr\n");

	kfree(mr);
	return 0;
}

int bluerdma_get_port_immutable(struct ib_device *ibdev, u32 port_num,
				struct ib_port_immutable *immutable)
{
	pr_info("bluerdma_get_port_immutable\n");
	struct ib_port_attr attr = {};
	int err;

	if (port_num != 1) {
		err = -EINVAL;
		dev_err(&ibdev->dev, "bad port_num = %d\n", port_num);
		goto err_out;
	}

	err = ib_query_port(ibdev, port_num, &attr);
	if (err)
		goto err_out;

	immutable->core_cap_flags = RDMA_CORE_CAP_PROT_USNIC;
	immutable->pkey_tbl_len = 1;
	immutable->gid_tbl_len = 1;

	return 0;

err_out:
	dev_err(&ibdev->dev, "returned err = %d", err);
	return err;
}

int bluerdma_alloc_ucontext(struct ib_ucontext *ibuc, struct ib_udata *udata)
{
	pr_info("bluerdma_alloc_ucontext\n");
	return 0;
}

void bluerdma_dealloc_ucontext(struct ib_ucontext *ibuc)
{
	pr_info("bluerdma_dealloc_ucontext\n");
}

int bluerdma_query_pkey(struct ib_device *ibdev, u32 port_num, u16 index,
			u16 *pkey)
{
	pr_info("bluerdma_query_pkey\n");
	*pkey = 1;
	return 0;
}

int bluerdma_query_gid(struct ib_device *ibdev, u32 port_num, int index,
		       union ib_gid *gid)
{
	struct bluerdma_dev *dev = to_bdev(ibdev);
	int i;

	pr_info("bluerdma_query_gid: %d\n", dev->id + 1);
	for (i = 0; i < 16; i++) {
		gid->raw[i] = dev->id + 1;
	}

	return 0;
}
