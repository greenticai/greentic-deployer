class GreenticOperatorCharm:
    """Machine charm scaffold for the Greentic operator."""

    def configure(self):
        return {
            "snap": "greentic-operator",
            "mode": "machine",
            "restart_on_change": True,
        }

