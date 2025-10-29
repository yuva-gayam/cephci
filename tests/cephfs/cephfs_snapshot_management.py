import traceback

from looseversion import LooseVersion

from ceph.ceph import CommandFailed
from tests.cephfs.cephfs_utilsV1 import FsUtils
from tests.cephfs.lib.cephfs_refinode_utils import RefInodeUtils
from utility.log import Log
from utility.retry import retry
from utility.utils import get_ceph_version_from_cluster

log = Log(__name__)


def run(ceph_cluster, **kw):
    """
    Pre-requisites :
    1. creats fs volume create cephfs_new
    2. ceph fs subvolumegroup create <vol_name> <group_name> --pool_layout <data_pool_name>
    3. ceph fs subvolume create <vol_name> <subvol_name> [--size <size_in_bytes>] [--group_name <subvol_group_name>]
       [--pool_layout <data_pool_name>] [--uid <uid>] [--gid <gid>] [--mode <octal_mode>]  [--namespace-isolated]
    4. Create Data on the subvolume → Data1 → say files 1, 2, 3

    snapshot Operations:
    1. ceph fs subvolume snapshot create <vol_name> <subvol_name> <snap_name> [--group_name <subvol_group_name>] → Snap1
       Write Data on Subvolume → Data2 -->say files 1,2,3 4,5,6
    2. ceph fs subvolume snapshot create <vol_name> <subvol_name> <snap_name> [--group_name <subvol_group_name>] → Snap2
       Write Data on Subvolume → Data3 -->say files 1,2,3 4,5,6 7,8,9 → Collect checksum
    3. Delete Data1 contents -->1,2,3
    4. Revert to Snap1(copy files from snap1 folder), then compare Data1_contents  == Data1 – >1,2,3 4,5,6 7,8,9
    5. Delete Data1 contents and Data2 Contents -->1,2,3 4,5,6
    6. Revert to Snap2(copy files from snap2 folder), then compare Data2_contents  == Data2 → 1,2,3 4,5,6 7,8,9
    7. ceph fs subvolume snapshot rm <vol_name> <subvol_name> <snap_name> [--group_name <subvol_group_name>] snap1
    8. ceph fs subvolume snapshot rm <vol_name> <subvol_name> <snap_name> → snap2

    Clean-up:
    1. ceph fs subvolume rm <vol_name> <subvol_name> [--group_name <subvol_group_name>]
    2. ceph fs subvolumegroup rm <vol_name> <group_name>
    3. ceph fs volume rm cephfs_new --yes-i-really-mean-it
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
        fs_util.prepare_clients(clients, build)
        fs_util.auth_list(clients)
        ref_inode_utils = RefInodeUtils(ceph_cluster)
        ceph_version = get_ceph_version_from_cluster(clients[0])
        log.info("checking Pre-requisites")
        if not clients:
            log.info(
                f"This test requires minimum 1 client nodes.This has only {len(clients)} clients"
            )
            return 1
        client1 = clients[0]
        results = []
        tc1 = "83571366"
        log.info(f"Execution of testcase {tc1} started")
        log.info("Create and list a volume")
        fs_name = "cephfs_new" if not erasure else "cephfs_new-ec"
        pool_name = (
            f"cephfs.{fs_name}.data" if not erasure else f"cephfs.{fs_name}.data-ec"
        )
        fs_details = fs_util.get_fs_info(client1, fs_name)

        if not fs_details:
            fs_util.create_fs(client1, fs_name)
        commands = [
            f"ceph fs subvolumegroup create {fs_name} snap_group {pool_name}",
            f"ceph fs subvolume create {fs_name} snap_vol --size 5368706371 --group_name snap_group",
        ]
        for command in commands:
            client1.exec_command(sudo=True, cmd=command)
            results.append(f"{command} successfully executed")

        if not fs_util.wait_for_mds_process(client1, f"{fs_name}"):
            raise CommandFailed("Failed to start MDS deamons")
        log.info("Get the path of sub volume")
        subvol_path, rc = client1.exec_command(
            sudo=True, cmd=f"ceph fs subvolume getpath {fs_name} snap_vol snap_group"
        )
        log.info("Make directory fot mounting")
        client1.exec_command(sudo=True, cmd="mkdir /mnt/mycephfs1")
        retry_mount = retry(CommandFailed, tries=3, delay=30)(fs_util.fuse_mount)
        retry_mount(
            [client1],
            "/mnt/mycephfs1",
            extra_params=f" -r {subvol_path.strip()} --client_fs {fs_name}",
        )
        base_path = "/mnt/mycephfs1"
        main_file = "%s/file1" % base_path
        if LooseVersion(ceph_version) > LooseVersion("20.1.1"):
            ref_inode_utils.allow_referent_inode_feature_enablement(
                client1, fs_name, enable=True
            )
            ref_inode_utils.create_directories(
                client1, base_path, ["dirA", "dirA/dirB"]
            )
            ref_inode_utils.create_file_with_content(
                client1, "%s/dirA/fileA1" % base_path, "data in file A1"
            )
            ref_inode_utils.create_file_with_content(
                client1, "%s/dirA/dirB/fileB1" % base_path, "data in file B1"
            )

            ref_inode_utils.create_file_with_content(
                client1, main_file, "original file content"
            )
            hardlinks = [
                "%s/file1_hardlink1" % base_path,
                "%s/file1_hardlink2" % base_path,
                "%s/dirA/file1_hardlink_in_dirA" % base_path,
            ]
            for hl in hardlinks:
                ref_inode_utils.create_hardlink_and_validate(
                    client1, fs_util, main_file, hl, pool_name, fs_name
                )

        fs_util.create_file_data(client1, "/mnt/mycephfs1", 3, "snap1", "snap_1_data ")
        client1.exec_command(
            sudo=True,
            cmd=f"ceph fs subvolume snapshot create {fs_name} snap_vol snap_1 --group_name snap_group",
        )

        fs_util.create_file_data(client1, "/mnt/mycephfs1", 3, "snap2", "snap_2_data ")
        client1.exec_command(
            sudo=True,
            cmd=f"ceph fs subvolume snapshot create {fs_name} snap_vol snap_2 --group_name snap_group",
        )

        fs_util.create_file_data(client1, "/mnt/mycephfs1", 3, "snap3", "snap_3_data ")
        expected_files_checksum = fs_util.get_files_and_checksum(
            client1, "/mnt/mycephfs1"
        )

        log.info("delete Files created as part of snap1")
        client1.exec_command(sudo=True, cmd="cd /mnt/mycephfs1;rm -rf snap1*")

        log.info("copy files from snapshot")
        client1.exec_command(
            sudo=True, cmd="cd /mnt/mycephfs1;cp -a .snap/_snap_1_*/* ."
        )

        snap1_files_checksum = fs_util.get_files_and_checksum(client1, "/mnt/mycephfs1")
        if expected_files_checksum != snap1_files_checksum:
            log.error("checksum is not matching after snapshot1 revert")
            return 1

        log.info("delete Files created as part of snap2")
        client1.exec_command(sudo=True, cmd="cd /mnt/mycephfs1;rm -rf snap2*")

        log.info("copy files from snapshot")
        client1.exec_command(
            sudo=True, cmd="cd /mnt/mycephfs1;cp -a .snap/_snap_2_*/* ."
        )

        snap2_files_checksum = fs_util.get_files_and_checksum(client1, "/mnt/mycephfs1")
        log.info(f"expected_files_checksum : {expected_files_checksum}")
        log.info(f"snap2_files_checksum : {snap2_files_checksum}")
        if expected_files_checksum != snap2_files_checksum:
            log.error("checksum is not matching after snapshot1 revert")
            return 1

        if LooseVersion(ceph_version) > LooseVersion("20.1.1"):
            ref_inode_utils.allow_referent_inode_feature_enablement(
                client1, fs_name, enable=False
            )

        log.info(f"Testcase {tc1} passed")
        return 0

    except Exception as e:
        log.info(e)
        log.info(traceback.format_exc())
        return 1

    finally:
        log.info("cleanup the system")

        log.info("unmount the drive")
        client1.exec_command(sudo=True, cmd="fusermount -u /mnt/mycephfs1")

        commands = [
            f"ceph fs subvolume snapshot rm {fs_name} snap_vol snap_1 --group_name snap_group",
            f"ceph fs subvolume snapshot rm {fs_name} snap_vol snap_2 --group_name snap_group",
            f"ceph fs subvolume rm {fs_name} snap_vol --group_name snap_group",
            f"ceph fs subvolumegroup rm {fs_name} snap_group",
            "ceph config set mon mon_allow_pool_delete true",
            f"ceph fs volume rm {fs_name} --yes-i-really-mean-it",
            "rm -rf /mnt/mycephfs1",
        ]
        for command in commands:
            client1.exec_command(sudo=True, cmd=command)
