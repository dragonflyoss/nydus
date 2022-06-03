class LinuxCommand:
    def __init__(self, command_name):
        self.command_name = command_name
        self.command_param_dict = {}
        self.command_flags = []
        self.command_name = command_name
        self.param_name_prefix = "--"
        self.param_separator = " "
        self.param_value_prefix = " "
        self.param_value_list_separator = ","
        self.subcommand = None

    def set_subcommand(self, subcommand):
        self.subcommand = subcommand
        return self

    def set_param(self, key, val):
        self.command_param_dict[key] = val
        return self

    def set_flags(self, *new_flag):
        for f in new_flag:
            self.command_flags.append(f)

        return self

    def remove_param(self, key):
        try:
            del self.command_param_dict[key]
        except KeyError:
            pass

    def __str__(self):
        if self.subcommand is not None:
            command = self.command_name + " " + self.subcommand
        else:
            command = self.command_name
        for key, value in self.command_param_dict.items():
            command += (
                f"{self.param_separator}{self.param_name_prefix}"
                f"{key}{self.param_value_prefix}{value}"
            )
        for flag in self.command_flags:
            command += f"{self.param_separator}{self.param_name_prefix}{flag}"
        return command
