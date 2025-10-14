from time import sleep

from nfs_operations import cleanup_cluster, open_mandatory_v3_ports, setup_nfs_cluster

from cli.ceph.ceph import Ceph
from cli.exceptions import ConfigError, OperationFailedError
from cli.utilities.filesys import Mount, Unmount
from utility.log import Log

log = Log(__name__)


def update_export_conf(
    client, nfs_name, nfs_export_readonly, original_access_type, new_access_type
):
    try:
        out = Ceph(client).nfs.export.get(nfs_name, nfs_export_readonly)
        client.exec_command(sudo=True, cmd=f"echo '{out}' > export.conf")
        client.exec_command(
            sudo=True,
            cmd=f"sed -i 's/{original_access_type}/{new_access_type}/g' export.conf",
        )
        Ceph(client).nfs.export.apply(nfs_name, "export.conf")
    except Exception:
        raise OperationFailedError("failed to edit access type in export conf file")


def run(ceph_cluster, **kw):
    """Verify readdir ops
    Args:
        **kw: Key/value pairs of configuration information to be used in the test.
    """
    config = kw.get("config")
    nfs_nodes = ceph_cluster.get_nodes("nfs")
    clients = ceph_cluster.get_nodes("client")
    port = config.get("port", "2049")
    version = config.get("nfs_version", "4.0")
    no_clients = int(config.get("clients", "2"))
    # If the setup doesn't have required number of clients, exit.
    if no_clients > len(clients):
        raise ConfigError("The test requires more clients than available")

    clients = clients[:no_clients]  # Select only the required number of clients
    nfs_node = nfs_nodes[0]
    fs_name = "cephfs"
    nfs_name = "cephfs-nfs"
    nfs_export = "/export"
    nfs_mount = "/mnt/nfs"
    nfs_server_name = nfs_node.hostname

    # Export Conf Parameter
    nfs_export_readonly = "/exportRO"
    nfs_readonly_mount = "/mnt/nfs_readonly"
    original_access_type = '"access_type": "RW"'
    new_access_type = '"access_type": "RO"'

    try:
        # Setup nfs cluster
        setup_nfs_cluster(
            clients,
            nfs_server_name,
            port,
            version,
            nfs_name,
            nfs_mount,
            fs_name,
            nfs_export,
            fs_name,
            ceph_cluster=ceph_cluster,
        )

        # Create export
        Ceph(clients[0]).nfs.export.create(
            fs_name=fs_name,
            nfs_name=nfs_name,
            nfs_export=nfs_export_readonly,
            fs=fs_name,
        )

        # Edit the export config to mount with access_type 'RO'
        update_export_conf(
            clients[0],
            nfs_name,
            nfs_export_readonly,
            original_access_type,
            new_access_type,
        )

        # Open the mountd port for RO export
        log.info("Check build version")
        build = config.get("build", config.get("rhbuild"))
        if build.startswith("7"):
            sleep(10)
            ports_to_open = ["portmapper", "mountd"]
            open_mandatory_v3_ports(nfs_node, ports_to_open)

        # Mount the RO export on client
        clients[0].create_dirs(dir_path=nfs_readonly_mount, sudo=True)
        if Mount(clients[0]).nfs(
            mount=nfs_readonly_mount,
            version=version,
            port=port,
            server=nfs_server_name,
            export=nfs_export_readonly,
        ):
            raise OperationFailedError(f"Failed to mount nfs on {clients[0].hostname}")
        log.info("Mount succeeded on client")

        # Test writes on Readonly export
        sleep(3)
        _, rc = clients[0].exec_command(
            sudo=True, cmd=f"touch {nfs_readonly_mount}/file_ro", check_ec=False
        )
        # Ignore the "Read-only file system" error and consider it as a successful execution
        if "touch: cannot touch" in str(rc) and "Read-only file system" in str(rc):
            log.info("As expected, failed to create file on RO export")
        else:
            log.error("Created file on RO export")
            return 1

        # Test writes on RW export
        if clients[0].exec_command(sudo=True, cmd=f"touch {nfs_mount}/file_rw"):
            log.info("Successfully created file on RW export")
        else:
            log.error("failed to create file on RW export")
            return 1
        return 0
    except Exception as e:
        log.error(f"Error : {e}")
        return 1
    finally:
        log.info("Cleaning up")
        sleep(30)
        # Clearning up the read only export and mount dir
        if Unmount(clients[0]).unmount(nfs_readonly_mount):
            raise OperationFailedError(
                f"Failed to unmount nfs on {clients[0].hostname}"
            )
        clients[0].exec_command(sudo=True, cmd=f"rm -rf  {nfs_readonly_mount}")
        Ceph(clients[0]).nfs.export.delete(nfs_name, nfs_export_readonly)

        # Cleaning up the remaining export and deleting the nfs cluster
        cleanup_cluster(clients, nfs_mount, nfs_name, nfs_export)
        log.info("Cleaning up successfull")
