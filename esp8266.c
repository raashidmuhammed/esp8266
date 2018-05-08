#include <linux/module.h>
#include <linux/tty.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>

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


/* Netdevice DOWN -> UP routine */
static int espnet_open(struct net_device *dev)
{
	printk("esp8266: espnet_open called\n");

	struct esp8266 *esp = netdev_priv(dev);

	if (esp->tty == NULL) {
		printk("esp8266: No TTY device\n");
		return -ENODEV;
	}

	netif_start_queue(dev);

	return 0;
}

static netdev_tx_t espnet_xmit(struct sk_buff *skb, struct net_device *dev)
{
	printk("esp8266: espnet_xmit called\n");

	int bytes;
	struct esp8266 *esp = netdev_priv(dev);
	unsigned char buf[] = {0x84, 0xde, 0xad, 0xf5, 0xb5, 0x7e};

	/* set_bit(TTY_DO_WRITE_WAKEUP, &esp->tty->flags); */
	bytes = esp->tty->ops->write(esp->tty, buf, sizeof(buf));
	printk("esp8266: Write complete: %d\n", bytes);

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
	ether_setup(dev);
	dev->netdev_ops		= &esp_netdev_ops;
	dev->destructor		= esp_free_netdev;

	dev->mtu		= 1500;
}

static int esptty_open(struct tty_struct *tty)
{
	int err;
	char name[IFNAMSIZ];
	struct esp8266 *esp;
	struct net_device *dev = NULL;
	unsigned char mac_addr[] = {0x5c, 0xcf, 0x7f, 0x0b, 0x9c, 0xb6};

	rtnl_lock();

	esp = tty->disc_data;
	sprintf(name, "esp%d", 0);
	dev = alloc_netdev(sizeof(*esp), name, NET_NAME_UNKNOWN, esp_setup);
	if (!dev) {
		rtnl_unlock();
		return -1;
	}

	ether_addr_copy(dev->dev_addr, mac_addr);
	ether_addr_copy(dev->perm_addr, mac_addr);

	esp = netdev_priv(dev);
	/* fixme: add magic check here */
	esp->dev = dev;
	esp->tty = tty;
	tty->disc_data = esp;

	err = register_netdevice(esp->dev);
	if (err) {
		printk("Netdevice registration failed.\n");
		esp->tty = NULL;
		tty->disc_data = NULL;
		rtnl_unlock();
		return err;
	}

	rtnl_unlock();

	tty->receive_room = 65536; /* Enables receive */

	return 0;
}

static void esptty_receive_buf(struct tty_struct *tty, const unsigned char *cp,
			       char *fp, int count)
{
	printk("esp8266: esptty_receive_buf called\n");

	struct esp8266 *esp = tty->disc_data;

	/* fixme: Add magic no check */

	/* Read the characters out of the buffer */
	printk("Data received: ");
	while (count--) {
		if (fp && *fp++) {
			if (!test_and_set_bit(ESPF_ERROR, &esp->flags))
				esp->dev->stats.rx_errors++;
			cp++;
			printk("esp8266: Parity Errors\n");
			continue;
		}
		printk(KERN_CONT "%02X", *cp++);
	}
}

static void esptty_close(struct tty_struct *tty)
{
	printk("esp8266: esptty_close called\n");

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

	status = tty_register_ldisc(N_ESP8266, &esp8266_ldisc);
	if (status) {
		printk(KERN_ERR "esp8266: can't register line discipline\n");
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
