from scapy.all import get_if_list


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def print_menu() -> str:
    """
    Display menu and input user choice

    :return: user choice
    """
    print("1. Capture traffic")
    print("2. Analyse traffic")
    print("3. Generate report")
    print("4. Exit")
    choice = input("Choose an option: ")
    return choice


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    int_list = get_if_list()
    interface = input(f"Choose an interface from the list {int_list}: ")
    return interface
