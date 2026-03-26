import docker
from docker.errors import NotFound, APIError

SANDBOX_NETWORK = "cybersentinel_sandbox-net"

TARGET_IMAGES = {
    "dvwa": "vulnerables/web-dvwa",
    # tu peux ajouter plus tard :
    # "webgoat": "webgoat/webgoat"
}


class SandboxManager:
    def __init__(self):
        self.client = docker.from_env()

    def ensure_network_exists(self):
        networks = self.client.networks.list(names=[SANDBOX_NETWORK])
        if networks:
            return networks[0]

        return self.client.networks.create(
            name=SANDBOX_NETWORK,
            driver="bridge",
            internal=True,
            ipam=docker.types.IPAMConfig(
                pool_configs=[
                    docker.types.IPAMPool(
                        subnet="172.22.0.0/16"
                    )
                ]
            )
        )

    def create_target_container(self, scan_id: str, target_type: str):
        self.ensure_network_exists()

        if target_type not in TARGET_IMAGES:
            raise ValueError(f"target_type non supporté: {target_type}")

        image_name = TARGET_IMAGES[target_type]
        container_name = f"sandbox-target-{scan_id}"

        # suppression préventive si existe déjà
        try:
            old = self.client.containers.get(container_name)
            old.stop()
            old.remove(force=True)
        except NotFound:
            pass

        container = self.client.containers.run(
            image=image_name,
            name=container_name,
            detach=True,
            network=SANDBOX_NETWORK,
            tty=True,
            stdin_open=False,
            labels={
                "project": "cybersentinel",
                "module": "sandbox",
                "scan_id": scan_id,
                "target_type": target_type
            }
        )

        target_url = f"http://{container_name}"

        return {
            "scan_id": scan_id,
            "container_name": container_name,
            "target_url": target_url,
            "network": SANDBOX_NETWORK,
            "status": "running"
        }

    def delete_target_container(self, scan_id: str):
        container_name = f"sandbox-target-{scan_id}"

        try:
            container = self.client.containers.get(container_name)
            container.stop(timeout=5)
            container.remove(force=True)

            return {
                "scan_id": scan_id,
                "container_name": container_name,
                "status": "deleted"
            }

        except NotFound:
            return {
                "scan_id": scan_id,
                "container_name": container_name,
                "status": "not_found"
            }

    def cleanup_all_sandboxes(self):
        containers = self.client.containers.list(all=True, filters={"label": "module=sandbox"})
        deleted = []

        for c in containers:
            try:
                deleted.append(c.name)
                c.stop(timeout=5)
                c.remove(force=True)
            except APIError:
                pass

        return {"deleted_containers": deleted}