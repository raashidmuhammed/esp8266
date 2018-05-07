#include <linux/module.h>
#include <linux/tty.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
//#include <linux/etherdevice.h>

#define N_ESP8266 26

MODULE_ALIAS_LDISC(N_ESP8266);
MODULE_DESCRIPTION("ESP8266 driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Raashid Muhammed <raashidmuhammed@zilogic.com>");


struct esp8266 {
	int			magic; /* fixme: Needs to added to code */

	struct tty_struct	*tty;
	struct net_device	*dev;

	unsigned long 		flags;
#define ESPF_ERROR		1	/* Parity error, etc. */
};

static struct net_device *esp_dev;


/* Netdevice DOWN -> UP routine */
static int espnet_open(struct net_device *dev)
{
	struct esp8266 *esp = netdev_priv(dev);
	/* unsigned char buf[] = {0x85, 0xab, 0x98, 0x9f, 0x13, 0x7e}; */

	if (esp->tty == NULL)
		return -ENODEV;

	netif_start_queue(dev);


	/* esp->tty->ops->write(esp->tty, buf, sizeof(buf)); */

	return 0;
}

static netdev_tx_t espnet_xmit(struct sk_buff *skb, struct net_device *dev)
{
	return NETDEV_TX_OK;
}

static int espnet_change_mtu(struct net_device *dev, int new_mtu)
{
	return 0;
}

/* Netdevice UP -> DOWN routine */
static int espnet_close(struct net_device *dev)
{
	struct esp8266 *esp = netdev_priv(dev);

	if (esp->tty) {
		/* TTY discipline is running. */
		clear_bit(TTY_DO_WRITE_WAKEUP, &esp->tty->flags);
	}
	netif_stop_queue(dev);

	return 0;
}

static const struct net_device_ops esp_netdev_ops = {
	.ndo_open               = espnet_open,
	.ndo_stop               = espnet_close,
	.ndo_start_xmit         = espnet_xmit,
	.ndo_change_mtu         = espnet_change_mtu,
};

static void esp_free_netdev(struct net_device *dev)
{
	free_netdev(dev);
}

static void esp_setup(struct net_device *dev)
{
	dev->netdev_ops		= &esp_netdev_ops;
	dev->destructor		= esp_free_netdev;

	dev->hard_header_len	= 0;
	dev->addr_len		= 0;
	dev->tx_queue_len	= 10;

	dev->mtu		= 1500;
	/* fixme: Need to set appropriate macro here */
	dev->type		= ARPHRD_ETHER;

	/* New-style flags. */
	//	dev->flags		= 0;
	//	dev->features           = NETIF_F_HW_CSUM;
}

static int esptty_open(struct tty_struct *tty)
{
	int err;
	char name[IFNAMSIZ];
	struct esp8266 *esp;
	struct net_device *dev = NULL;
	/* unsigned char mac_addr[] = {0x5c, 0xcf, 0x7f, 0x0b, 0x9c, 0xb6}; */

	dev = esp_dev;
	if (dev == NULL) {
		printk("esp8266: Null device\n");
		return -1;
	}

	rtnl_lock();

	esp = tty->disc_data;
	sprintf(name, "esp%d", 0);
	dev = alloc_netdev(sizeof(*esp), name, NET_NAME_UNKNOWN, esp_setup);
	if (!dev) {
		rtnl_unlock();
		return -1;
	}

	dev->base_addr = 0;
	esp = netdev_priv(dev);
	/* fixme: add magic check here */
	esp->dev = dev;
	esp->tty = tty;
	tty->disc_data = esp;

	/* ether_addr_copy(dev->dev_addr, mac_addr); */

	err = register_netdevice(esp->dev);
	if (err) {
		printk("Netdevice registration failed.\n");
		esp->tty = NULL;
		tty->disc_data = NULL;
		rtnl_unlock();
		return err;
	}

	rtnl_unlock();
	return 0;
}

static void esptty_receive_buf(struct tty_struct *tty, const unsigned char *cp,
			       char *fp, int count)
{
	struct esp8266 *esp = tty->disc_data;

	/* fixme: Add magic no check */

	/* Read the characters out of the buffer */
	while (count--) {
		if (fp && *fp++) {
			if (!test_and_set_bit(ESPF_ERROR, &esp->flags))
				esp->dev->stats.rx_errors++;
			cp++;
			continue;
		}
		printk("Data: received: %s", cp);
	}

}

static void esptty_close(struct tty_struct *tty)
{
	struct esp8266 *esp = (struct esp8266 *) tty->disc_data;

	tty->disc_data = NULL;
	esp->tty = NULL;
	unregister_netdev(esp->dev);
}


static struct tty_ldisc_ops esp8266_ldisc = {
	.owner		= THIS_MODULE,
	.magic		= TTY_LDISC_MAGIC,
	.name		= "esp8266",
	.open		= esptty_open,
	.close		= esptty_close,
	.receive_buf 	= esptty_receive_buf,
};

static int __init esp8266_init(void)
{
	int status;

	pr_info("esp8266: ESP8266 network driver\n");

	esp_dev = kzalloc(sizeof(struct net_device *), GFP_KERNEL);
	if (!esp_dev)
		return -ENOMEM;

	status = tty_register_ldisc(N_ESP8266, &esp8266_ldisc);
	if (status) {
		printk(KERN_ERR "esp8266: can't register line discipline\n");
		kfree(esp_dev);
	}
	return status;
}

static void __exit esp8266_exit(void)
{
	int ret;

	ret = tty_unregister_ldisc(N_ESP8266);
	if (ret)
		printk(KERN_ERR "esp8266: can't unregister ldisc (err %d)\n", ret);
}

module_init(esp8266_init);
module_exit(esp8266_exit);
