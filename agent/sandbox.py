import docker
import os
import tarfile
import io

class DockerSandbox:
    def __init__(self):
        try:
            self.client = docker.from_env()
        except docker.errors.DockerException as e:
            raise RuntimeError(
                "Docker daemon not found or not running. Start Docker Desktop (or ensure your Docker daemon is accessible via DOCKER_HOST), then retry. Original error: "
                + str(e)
            )
        self.image_tag = "cortensor-sandbox:latest"

    def build_image(self):
        """Ensures the sandbox image exists."""
        path = os.path.join(os.getcwd(), 'sandbox_env')
        print(f"🐳 Building Sandbox Image from {path}...")
        self.client.images.build(path=path, tag=self.image_tag)

    def run_verification(self, code_patch, test_code):
        """
        Spins up a container, injects code, runs tests, and destroys itself.
        Returns: {success: bool, logs: str}
        """
        try:
            # Create a temporary container
            container = self.client.containers.run(
                self.image_tag,
                command="python -m pytest test_suite.py",
                detach=True,
                network_mode="none", # 🛡️ SECURITY: No Internet Access
                mem_limit="128m"
            )

            # Inject the code and tests into the container
            self._copy_to_container(container, "solution.py", code_patch)
            self._copy_to_container(container, "test_suite.py", test_code)

            # Wait for execution
            result = container.wait()
            logs = container.logs().decode('utf-8')
            container.remove()

            success = result['StatusCode'] == 0
            return {"success": success, "logs": logs}

        except Exception as e:
            return {"success": False, "logs": str(e)}

    def _copy_to_container(self, container, filename, content):
        """Helper to inject in-memory files into Docker"""
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode='w') as tar:
            data = content.encode('utf-8')
            tarinfo = tarfile.TarInfo(name=filename)
            tarinfo.size = len(data)
            tar.addfile(tarinfo, io.BytesIO(data))
        tar_stream.seek(0)
        container.put_archive('/app', tar_stream)
