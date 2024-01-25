"""
This module defines the main PynTester class which is used to run the CLI tool.
"""

import cmd2

from commands import INSTALLED_COMMANDS
from config import PyntesterConfig
from utils.banner import BANNER
from utils.colors import Colors


class PynTester(cmd2.Cmd):
    """
    The PynTester class is the main class for the CLI tool. It loads the configuration,
    initializes the commands, and provides methods to run the tool and execute commands.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the PynTester instance. Load the configuration and initialize the commands.
        """
        super().__init__(*args, **kwargs)

        # Customize the prompt and intro message
        self.prompt = f"{Colors.BOLD}{Colors.OKCYAN}(PynTester) {Colors.ENDC}> "
        self.intro = BANNER

        builtin_commands = ['alias', 'edit', 'macro', 'run_pyscript', 'run_script', 'shortcuts']
        for c in builtin_commands:
            delattr(cmd2.Cmd, 'do_' + c)

        self.pytester_config = PyntesterConfig()
        self.pytester_config.load_from_file()

        self.load_settable_configuration()

    def do_clear(self, _) -> None:
        """
        Clear the screen.
        """
        self.do_shell('clear') # noqa

    def load_settable_configuration(self):
        for param_name, param in self.pytester_config.get_settable_params():
            setattr(self, param_name, param['value'])
            self.add_settable(
                cmd2.Settable(param_name, param['type'], param['description'], self, **param.get('kwargs', {}))
            )

    # def load_commands(self):
    #     for cmd in INSTALLED_COMMANDS:
    #         cmd_instance = cmd(self)
    #         setattr(self, f"do_{cmd.cid}", cmd_instance.execute)
    #         setattr(self, f"help_{cmd.cid}", cmd_instance.help())
    #
    #         for alias in cmd.aliases:
    #             setattr(self, f"do_{alias}", cmd_instance.execute)
    #             setattr(self, f"help_{alias}", cmd_instance.help())


if __name__ == '__main__':
    app = PynTester(command_sets=INSTALLED_COMMANDS)
    app.cmdloop()
