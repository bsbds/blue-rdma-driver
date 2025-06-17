// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#ifndef __BLUERDMA_H__
#define __BLUERDMA_H__

#include <linux/pci.h>
#include <linux/netdevice.h>
#include <rdma/ib_verbs.h>
#include <linux/sysfs.h>
#include <linux/device.h>

#define BLUERDMA_DEFAULT_MTU 1500
#define BLUERDMA_MAC_PREFIX 0x02, 0xBD, 0xBD, 0x00, 0x00
#define BLUERDMA_GID_TABLE_SIZE 16  /* Standard size for GID tables */

struct bluerdma_gid_entry {
	union ib_gid gid;
	struct ib_gid_attr attr;
	bool valid;
};

struct bluerdma_dev {
	struct ib_device ibdev;
	struct net_device *netdev;
	struct pci_dev *pdev;

	struct ib_device_attr attr;
	struct ib_port_attr port_attr;
	enum ib_port_state state;

	int id;
	
	/* Network device specific */
	struct napi_struct napi;
	u8 mac_addr[ETH_ALEN];
	spinlock_t tx_lock;
	spinlock_t mac_lock;  /* Lock for MAC address protection */
	
	/* GID table */
	struct bluerdma_gid_entry gid_table[BLUERDMA_GID_TABLE_SIZE];
	spinlock_t gid_lock;
	
	/* sysfs attributes */
	struct device_attribute gids_attr;
	struct device_attribute mac_attr;
};

static inline struct bluerdma_dev *to_bdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct bluerdma_dev, ibdev);
}

struct bluerdma_pd {
	struct ib_pd ibpd;
};

struct bluerdma_cq {
	struct ib_cq ibcq;
};

struct bluerdma_qp {
	struct ib_qp ibqp;
};

struct bluerdma_ucontext {
	struct ib_ucontext ibuc;
};

#endif // __BLUERDMA_H__
