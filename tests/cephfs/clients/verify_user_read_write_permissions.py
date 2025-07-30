import random
import string
import traceback

from tests.cephfs.cephfs_utilsV1 import FsUtils
from utility.log import Log

log = Log(__name__)


def run(ceph_cluster, **kw):
    """
    Test Steps:
    1. Create a user with * permission
    2. Mount the cephfs with the user
    3. Check if the user has the permission to write
    4. Change the permission to read only
    5. Check if the user has the permission to not write
    """

    try:
        test_data = kw.get("test_data")
        fs_util = FsUtils(ceph_cluster, test_data=test_data)
        erasure = (
            FsUtils.get_custom_config_value(test_data, "erasure")
            if test_data
            else False
        )
        config = kw.get("config")
        build = config.get("build", config.get("rhbuild"))
        clients = ceph_cluster.get_ceph_objects("client")
        log.info("checking Pre-requisites")
        fs_util.prepare_clients(clients, build)
        fs_util.auth_list(clients)
        default_fs = "cephfs_rw" if not erasure else "cephfs_rw-ec"
        fs_details = fs_util.get_fs_info(clients[0], default_fs)

        if not fs_details:
            fs_util.create_fs(clients[0], default_fs)
        mounting_dir = "".join(
            random.choice(string.ascii_lowercase + string.digits)
            for _ in list(range(5))
        )
        user_name = "".join(
            random.choice(string.ascii_lowercase + string.digits)
            for _ in list(range(5))
        )
        create_cmd = (
            f"ceph auth get-or-create client.{user_name} mon 'allow *'"
            f" mds 'allow * path=/'"
            f" osd 'allow *'"
            f" -o /etc/ceph/ceph.client.{user_name}.keyring"
        )
        clients[0].exec_command(sudo=True, cmd=create_cmd)
        client1 = clients[0]
        kernel_mounting_dir_1 = f"/mnt/cephfs_kernel{mounting_dir}_1/"
        fuse_mounting_dir_1 = f"/mnt/cephfs_fuse{mounting_dir}_1/"
        mon_node_ips = fs_util.get_mon_node_ips()
        fs_util.kernel_mount(
            [client1],
            kernel_mounting_dir_1,
            ",".join(mon_node_ips),
            extra_params=f",fs={default_fs}",
        )
        client1.exec_command(sudo=True, cmd=f"mkdir -p {fuse_mounting_dir_1}")
        client1.exec_command(
            sudo=True,
            cmd=f"ceph-fuse -n client.{user_name} {fuse_mounting_dir_1} --client_fs {default_fs}",
        )
        log.info("checking if the client has the permission to write")
        client1.exec_command(
            sudo=True,
            cmd=f"dd if=/dev/zero of={fuse_mounting_dir_1}_dd bs=100M " f"count=5",
        )
        client1.exec_command(
            sudo=True, cmd=f"ceph auth caps client.{user_name} mds 'allow r path=/'"
        )
        log.info("checking if the client has the permission to not write")
        out1, err = client1.exec_command(
            sudo=True,
            cmd=f"dd if=/dev/zero of={fuse_mounting_dir_1}_dd bs=100M " f"count=5",
            check_ec=False,
        )
        if err:
            return 0

    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        return 1
    finally:
        fs_util.client_clean_up(client1, kernel_mounting_dir_1, fuse_mounting_dir_1)
        fs_util.remove_fs(client1, default_fs)
        fs_util.validate_fs_services(
            client1, service_name=f"mds.{default_fs}", is_present=False
        )
