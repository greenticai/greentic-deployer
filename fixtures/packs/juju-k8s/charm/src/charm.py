class GreenticOperatorK8sCharm:
    """Kubernetes charm scaffold for the Greentic operator."""

    def configure(self):
        return {
            "mode": "k8s",
            "status_mapping": {
                "warming": "waiting",
                "ready": "active",
                "degraded": "blocked",
                "failed": "blocked"
            }
        }

