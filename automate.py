import subprocess
import getpass
from tabulate import tabulate
import argparse
import logging
import re
import sys
import os
from config import PATH, DOMAIN_JOIN, NAGIOS_DEP, NAGIOS_CLIENT, SPLUNK, CODE_PATH, LOG_PATH, NAGIOS_COMPONENTS, SPLUNK_LIST, SPLUNK_INPUT_LIST

error_ips = set()

LOG_PATH = f"{LOG_PATH}/script.log"
HOST_FILE = f"{CODE_PATH}/hosts.yml"

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler(f"{LOG_PATH}")
])

logging.info('')
logging.info('=========================> STARTED <==========================')
logging.info('')
logging.info('Automation has started ...')

def main():
    try:
        # Whatever the context in file "hosts.yml" make it empty at starting.
        clear_file(f"{HOST_FILE}")

        if args.ip_address:
            print('IP Address:', args.ip_address)
            if valid_ip(args.ip_address) == True:
                hosts = [args.ip_address]  # Directly pass the provided IP address
                logging.info('Executing for IP Address: %s' % args.ip_address)

                # Here ip add in hosts.yml file
                host_modify = f"{HOST_FILE}"
                ip_address_add = f"{args.ip_address}"
                add_line(host_modify, ip_address_add)
                ######################################

                inventory_file = f"{HOST_FILE}"
            elif valid_ip(args.ip_address) == False:
                print ("Please validate the provided IP range and proceed again")
                sys.exit(1)

        elif args.inventory_file:
            print('Inventory File:', args.inventory_file)
            inventory_file = args.inventory_file

            #List the host one by one
            with open(f"{inventory_file}", 'r') as file:
                hosts = [line.strip() for line in file if line.strip()]
                Host_IP = ', '.join(map(str, hosts))
                logging.info('Executing for IP Addresses: %s' % Host_IP)
        else:
            print('Please select the right argument')
        
        # Varify username, Password and hosts 
        check_user(hosts=hosts)

        # Here calling limit-host 
        if args.ip_address:
            hostname = HOSTNAMES[0]
            limit_host = f"{hostname}"
        elif args.inventory_file:
            limit_host = "all"

        # only Ansible installation is called
        if args.domain:
            domain_join(limit_host=limit_host, hosts=hosts, name=name)
            logging.info('==========================> ENDED <===========================')
            sys.exit(1)

        # only Nagios installation is called
        elif args.nagios:
            nag_dep(limit_host=limit_host, hosts=hosts, name=name)
            nagios_yml(limit_host=limit_host, name=name)
            logging.info('==========================> ENDED <===========================')
            sys.exit(1)

        # only Splunk installation is called
        elif args.splunk:
            splunk_install(limit_host=limit_host, hosts=hosts, name=name)
            logging.info('==========================> ENDED <===========================')
            sys.exit(1)

        # Enter the installation loop and each installation contain multiple functions
        while True:
            # Whatever the context in file "hosts.yml" make it empty at starting.
            clear_file(f"{HOST_FILE}")

            # It installation loop start from here
            print("1) Domain     2) Nagios     3) Splunk       4) Exit")
            print()
            pkg = input("Select what you want to install (e.g., '1' for Domain installation): ").lower()

            if not pkg:
                print("Input is blank. Please try again.")
                print()
                continue

            if pkg == "1" or pkg == "Domain":
                print("========================#  Anible installation is starting  #========================\n")
                if not error_ips:
                    domain_ret_code = domain_join(limit_host=limit_host, hosts=hosts, name=name)
                    if domain_ret_code == 0:
                        print(f"Installation has been completed")
                    elif domain_ret_code != 0:
                        while True:
                            require = input("Do you want to continue (y/n): ").lower()
                            if not require:
                                print("Input is blank. Please try again.")
                                print()
                                continue
                            elif require == "y":
                                domain_join(limit_host=limit_host, hosts=hosts, name=name)
                            elif require == "n":
                                break
                else:
                    print("Ansible installation can't be done. Please resolve the error manually or remove the IP Address from the inventory inorder to execute Ansible functionality successfully.")
                    print()
                    continue
            elif pkg == "2" or pkg == "nagios":
                print("========================#  Nagios installation is starting  #========================")
                print()
                if not error_ips:
                    while True:
                        depen = input("Do you want to proceed with nagios client installation (y/n): ").lower()
                        if not depen:
                            print("Input is blank. Please try again.")
                            print()
                            continue
                        elif depen == "y":
                            nag_dep_ret_code = nag_dep(limit_host=limit_host, hosts=hosts, name=name)
                            if nag_dep_ret_code == 0:
                                print(f"Nagios dependency Installation has been completed...Proceeding with client installation!!")
                                logging.info(f"Sucessfully installed nagios-perl-packages")
                                nag_client_ret_code = nagios_yml(limit_host=limit_host, name=name)
                                if nag_client_ret_code == 0:
                                    print(f"Installation has been completed")
                                    logging.info(f"Sucessfully installed nagios-Client")
                                    break
                                else:
                                    print(f"An error occurred for host ")
                                    logging.error(f"Getting error while installing the nagios-Client")
                                    continue
                            else:
                                print(f"An error occurred for above hosts ")
                                continue
                        elif depen == "n":
                            break
                        else:
                            print("Please provide the valid option.")
                            print()
                else:
                    print("Nagios installation can't be done. Please resolve the error manually or remove the IP Address from the inventory inorder to execute Nagios functionality successfully.")
                    print()
                    continue
            elif pkg == "3" or pkg == "splunk":
                print("========================#  Splunk installation is starting  #========================")
                print()
                splunk_ret_code = splunk_install(limit_host=limit_host, hosts=hosts, name=name)
                if splunk_ret_code == 0:
                    print(f"Splunk Installation has been completed ")
                else:
                    print(f"An error occurred for host ")
                print()
            elif pkg == "4" or pkg == "exit":
                print()
                logging.info(f'User has exited the script')
                logging.info('')
                print("========================#  Thank you for using this script  #========================")
                print()
                break
            else:
                print("Please provide the right option.")
                print()

    except KeyboardInterrupt:
        print("\n")
        print("\nScript terminated by user.")
        logging.warning(f'Script is terminated by user')
        logging.info('')
        logging.info('==========================> ENDED <===========================')
        sys.exit(1)    

    return limit_host, inventory_file, hosts

def user_detail():
    while True:
        try:
            print("Please provide your corp username before proceeding")
            global name
            name = input("Enter your CORP username: ").lower()
            logging.info('Script is running by user: %s' % name)
            
            if not name:
                print("Input is blank. Please try again.")
                continue
            print("Welcome, " + name)

        except Exception as e:
            print("An error occurred:", e)

        except KeyboardInterrupt:
            print("\n")
            print("\nScript terminated by user.")
            logging.warning('Script is terminated by user')
            logging.info('')
            logging.info('==========================> ENDED <===========================')
            sys.exit(1)
        break
    return name

def clear_file(file_path):
    with open(file_path, "w") as f:
        pass
 
def valid_ip(ip):
    # Regular expression pattern for IPv4s
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        return True
    else:
        return False

def run_subprocess(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0, universal_newlines=True)
        for line in process.stdout:
            std_line = line.replace("\n", "")
            rst_line = ''.join(std_line)
            logging.debug(rst_line)
            print(line, end='')
        process.communicate()
        return process.returncode
    except Exception as e:
        logging.error(f"Error running command: {e}")
        return None

def check_user(hosts):
    print("=======================# User Authentication for Servers #========================.\n")
    # Taking user_id and Password information
    logging.info('Taking user_id and Password information for "User Authentication"')
    user = input("Enter the Username: ")
    logging.info(f'Select user is {user}')
    password = getpass.getpass("Enter the Password: ")

    #Validate user id and password by val_ipadd funcation
    print("\n===================# Validating Hostname and IP Address #=====================.\n")
    val_ipadd(user=user, password=password, hosts=hosts)

    print("\n")
    return


# Checking Hostname and IP Address is working or not
def parse_arguments():
    # Parse arguments
    parser = argparse.ArgumentParser(description='This Script for Domain-joining, Nagios and Splunk installation\n')

    #if ip is work then iventory is not working vice versa
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--inventory', dest='inventory_file', help='Path to the inventory file')
    group.add_argument('-ip', '--ip_address', help='IP address')

    #For single installaion
    parser.add_argument('--domain', action='store_true', help='Perform Domain installation')
    parser.add_argument('--nagios', action='store_true', help='Perform Nagios installation')
    parser.add_argument('--splunk', action='store_true', help='Perform Splunk installation')
    return parser.parse_args()


def val_ipadd(user, password, hosts):
    table_data = []
    global HOSTNAMES
    HOSTNAMES = []
    if not user or not password:
        print("Input is blank. Try again\n")
        return

    for host in hosts:
        try:
            logging.info('Validating user_id and Password')
            ssh_command = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {user}@{host} 'hostname'"
            result = subprocess.run(ssh_command, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                logging.info('Successfully Validated user_id and Password')
                hostname = result.stdout.strip()
                table_data.append([hostname, host])
                HOSTNAMES.append(hostname)
            else:
                error_msg = result.stderr.strip() if result.stderr else "Error"
                table_data.append([error_msg, host])
                logging.warning('Getting error while validating UserId and Password')
                logging.error(f'{error_msg}')
        except subprocess.CalledProcessError as e:
            table_data.append([f"Error: {e.stderr.strip()}", host])
        except Exception as e:
            table_data.append([f"Error: {str(e)}", host])
    logging.info('The Hostname of the server is:  %s' % HOSTNAMES)

    headers = ["Hostname", "IP Address"]
    table = tabulate(table_data, headers, tablefmt="grid")
    print(table)
    return HOSTNAMES
       
# This function is working for negios dependecies insatllation on each Host
def nag_dep(limit_host, hosts, name):
    logging.info(f'{name} has selected Nagios-Dependencies')
    try:
        complex_hosts = []
        for HOSTNAME, ip_address in zip(HOSTNAMES, hosts):
            complex_host = f"{HOSTNAME} ansible_ssh_host={ip_address}"
            complex_hosts.append(complex_host)
        # Write the complex host entries to the output file
        with open(f"{HOST_FILE}", "w") as f:
            f.write("\n".join(complex_hosts) + "\n")

        #change the Directory
        os.chdir(PATH)

        #running command in specific directory
        nagios_dep_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{NAGIOS_DEP} --ask-pass"
        #print(f"Running Ansible command: {ansible_command}")
        logging.info(f'Running Command: {nagios_dep_command}')
        result = run_subprocess(nagios_dep_command)
        print()
        return result

    except KeyboardInterrupt:
            print("\n")
            print("\nScript terminated by user.")
            logging.warning('Script is terminated by user')
            logging.info('')
            logging.info('==========================> ENDED <===========================')
            sys.exit(1)

    

# This function calling nagios yml file and running nagios ansible script
def nagios_yml(limit_host, name):
    logging.info(f'{name} has selected Nagios-Client')
    try:
        print("Nagios script installation, some input is required\n")
        #print("1) dca-prd-nag201\n2) sfo-prd-nag201\n3) iad-prd-nag102\n4) sjc-prd-nag102\n5) sfo-pn1-nag201\n6) sfo-pn2-nag201")
        print("1) dca       2) sfo      3) iad      4) sjc      5) pn1      6) pn2\n")
        nag_server = input("Please Select the Nagios Server Cluster: ").lower()

        if not nag_server:
            print("\n")
            print("Input is blank. Please try again.")
            logging.warning('User has not selected any "Nagios-Server"')
            print("\n")
            return

        if nag_server == "1" or nag_server == "dca":
            nag_server = "dca-prd-nag201"
        elif nag_server == "2" or nag_server == "sfo":
            nag_server = "sfo-prd-nag201"
        elif nag_server == "3" or nag_server == "iad":
            nag_server = "iad-prd-nag102"
        elif nag_server == "4" or nag_server == "sjc":
            nag_server = "sjc-prd-nag102"
        elif nag_server == "5" or nag_server == "pn1":
            nag_server = "sfo-pn1-nag201"
        elif nag_server == "6" or nag_server == "pn2":
            nag_server = "sfo-pn2-nag201"
        else:
            print("Please provide the right option.")
            logging.warning('User has selected wrong "Nagios-Server" while using the script')
            print()
            return
        
        print(f'{nag_server}')

        #NAGIOS_COMPONENTS = ['adbut', 'blog', 'ccutl', 'cliq', 'cntws', 'cprgw', 'gc', 'gemfire', 'gw', 'hdpnn', 'kafk', 'lstdb', 'memkw', 'msg', 'ngw', 'pemdb', 'qimt', 'rstc', 'smtp', 'sprk', 'udep', 'uxes', 'uxwd', 'wsux', 'akka', 'cas', 'ccweb', 'clqdb', 'cpr', 'default', 'gdcs', 'gemgw', 'hbsdn', 'hmq', 'kzoo', 'mblmt', 'merc', 'msws', 'nre', 'pmnps', 'qiut', 'shd', 'soc', 'srch', 'udpdb', 'uxhc', 'varn', 'zoo', 'amq', 'cc', 'cep', 'cntap', 'cpr1', 'dns', 'gdlc', 'geoof', 'hbsnn', 'hqldp', 'lensa', 'mdb', 'mgdb', 'mtc', 'nrecs', 'pmpdb', 'rds', 'smgc', 'solr', 'ssolr', 'ukbkw', 'uxmt', 'vw', 'bcn', 'ccadm', 'civarn', 'cntdb', 'cpr2', 'dt', 'gem', 'gl', 'hddn', 'io', 'lenss', 'mem', 'mon', 'nag', 'pai', 'qidn', 'rst', 'smgdb', 'splunk', 'szoo', 'ukmdb', 'uxnd', 'wsrt']

        # Create chunks of data for each column
        num_columns = 6
        chunked_data = [NAGIOS_COMPONENTS[i:i + num_columns] for i in range(0, len(NAGIOS_COMPONENTS), num_columns)]

        # Fill shorter chunks with empty strings to align columns
        max_length = max(len(chunk) for chunk in chunked_data)
        for chunk in chunked_data:
            chunk.extend([''] * (max_length - len(chunk)))

        # Transpose the data for tabulation
        transposed_data = list(map(list, zip(*chunked_data)))

        # Print the tabulated data without headers
        table = tabulate(transposed_data, tablefmt='grid', headers=[])
        print(table)

        logging.info(f'{name} has selected "Nagios-server" is: %s' % nag_server)

        com_inp = input("\nPlease select componenets from above table: ").lower()

        logging.info(f'{name} has selected "Nagios-Component" is: %s' % com_inp)

        nagios_ser = nag_server

        #change the Directory
        os.chdir(PATH)

        #running command in specific directory
        nagios_client_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{NAGIOS_CLIENT} -e \"nagios_server={nagios_ser}\" -e 'component={com_inp}' --ask-pass"
        #print(f"Running Ansible command: {ansible_command}")
        logging.info(f'Running Command: {nagios_client_command}')
        result = run_subprocess(nagios_client_command)
        print("\n")
        return result
    except KeyboardInterrupt:
            print("\n")
            print("\nScript terminated by user.")
            logging.warning('Script is terminated by user')
            logging.info('')
            logging.info('==========================> ENDED <===========================')
            sys.exit(1)

def domain_join(limit_host, hosts, name):
    logging.info(f'{name} has selected Ansible/Domain-Joining')
    try:
        print("For Ansible_Push installation, some input is required\n")
        print("1) dv1  2) qa1  3) pn1  4) pn2  5) dca  6) sfo  7) iad  8) sc5-dev  9) sc5\n")
        env = input("Please select the 'riq_env' from the options above: ").lower()

        if not env:
            print("Input is blank. Please try again.")
            logging.warning('User has not selected any "RIQ_ENV"')
            print()
            return

        ansible_command = None

        complex_hosts = []
        for HOSTNAME, ip_address in zip(HOSTNAMES, hosts):
            complex_host = f"{HOSTNAME} ansible_ssh_host={ip_address}"
            complex_hosts.append(complex_host)

        # Write the complex host entries to the output file
        with open(f"{HOST_FILE}", "w") as f:
            f.write("\n".join(complex_hosts) + "\n")


        if env == "1" or env == "dv1":
            ansible_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{DOMAIN_JOIN} -e \"riq_env=dv1\" --ask-pass"
        elif env == "2" or env == "qa1":
            ansible_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{DOMAIN_JOIN} -e \"riq_env=qa1\" --ask-pass"
        elif env == "3" or env == "pn1":
            ansible_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{DOMAIN_JOIN} -e \"riq_env=pn1\" --ask-pass"
        elif env == "4" or env == "pn2":
            ansible_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{DOMAIN_JOIN} -e \"riq_env=pn2\" --ask-pass"
        elif env == "5" or env == "dca":
            ansible_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{DOMAIN_JOIN} -e \"riq_env=dca\" --ask-pass"
        elif env == "6" or env == "sfo":
            ansible_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{DOMAIN_JOIN} -e \"riq_env=sfo\" --ask-pass"
        elif env == "7" or env == "iad":
            ansible_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{DOMAIN_JOIN} -e \"riq_env=iad\" --ask-pass"
        elif env == "8" or env == "sc5-dev":
            ansible_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{DOMAIN_JOIN} -e \"riq_env=sc5-dev\" --ask-pass"
        elif env == "9" or env == "sc5":
            ansible_command = f"ansible-playbook -i {HOST_FILE} --limit={limit_host} {PATH}/{DOMAIN_JOIN} -e \"riq_env=sc5\" --ask-pass"
        else:
            print("Please provide the right option.")
            logging.warning('User has selected wrong "RIQ_ENV" while using the script')
            print()
            return

        logging.info('Selected Ansible "riq_env" type is: %s' % env)

        #change the Directory
        os.chdir(PATH)

        if ansible_command:
            logging.info(f'Running Command: {ansible_command}')
            #running command in specific directory
            result = run_subprocess(ansible_command)
            print("\n")
        return result
    
    except KeyboardInterrupt:
        print("\n")
        print("\nScript terminated by user.")
        logging.warning('Script is terminated by user')
        logging.info('')
        logging.info('==========================> ENDED <===========================')
        sys.exit(1)

def prepend_word(file_path, new_word):
    with open(file_path, 'r+') as file:
        content = file.read()
        file.seek(0, 0)  # Move the file pointer to the beginning
        file.write(new_word + content)

def remove_word(file_path, word_remove):
    with open(file_path, 'r+') as file:
        lines = file.readlines()  # Read all lines into a list
        file.seek(0)  # Move the file pointer to the beginning
        file.truncate()  # Clear the file's content
        for line in lines:
            line = line.replace(word_remove, '')  # Remove the specific word
            file.write(line)

def add_line(file_name, new_line):
    # Read the contents of the original file
    with open(file_name, 'r') as original_file:
        original_contents = original_file.read()

    # Create a temporary file and write the new line to it
    with open(file_name, 'w') as temp_file:
        temp_file.write(new_line + '\n')
        temp_file.write(original_contents)
    return temp_file.name

def remove_line(file_name, line_remove):
    with open(file_name, 'r') as file:
        lines = file.readlines()

    with open(file_name, 'w') as file:
        for line in lines:
            if line.strip() != line_remove:
                file.write(line)
    return file.name

def append_line(file_path, line):
    with open(file_path, 'a') as file:
        file.write(line + '\n')

def splunk_install(hosts, limit_host, name):
    logging.info(f'{name} has selected Splunk Process')
    try:
        print("Splunk script installation, some input is required\n")
        print("1) dca       2) sfo      3) iad      4) sjc      5) pn1      6) pn2\n")
        splunk_colo = input("Please select splunk indexer cluster from above: ").lower()

        if not splunk_colo:
            print("\n")
            print("Input is blank. Please try again.")
            logging.warning('User has not selected any "Splunk-Cluster"')
            print("\n")
            return

        if splunk_colo == "1" or splunk_colo == "dca":
            splunk_colo = "dca"
            splunk_idx = "null"
        elif splunk_colo == "2" or splunk_colo == "sfo":
            splunk_colo = "sfo"
            splunk_idx = "null"
        elif splunk_colo == "3" or splunk_colo == "iad":
            splunk_colo = "iad"
            splunk_idx = "null"
        elif splunk_colo == "4" or splunk_colo == "sjc":
            splunk_colo = "sjc"
            splunk_idx = "null"
        elif splunk_colo == "5" or splunk_colo == "pn1":
            print("1) sfo-pn1-spidx01.pn1.ci.lan       2) sfo-pn1-spidx02.pn1.ci.lan\n")
            splunk_idx_no = input("Please select the splunk indexer node: ").lower()
            if splunk_idx_no == "1":
                splunk_idx = "sfo-pn1-spidx01.pn1.ci.lan"
            elif splunk_idx_no == "2":
                splunk_idx = "sfo-pn1-spidx02.pn1.ci.lan"
            splunk_colo = "pn1"
        elif splunk_colo == "6" or splunk_colo == "pn2":
            print("1) sfo-pn2-spidx01.pn2.ci.lan       2) sfo-pn2-spidx02.pn2.ci.lan\n")
            splunk_idx_no = input("Please select the splunk indexer node: ").lower()
            if splunk_idx_no == "1":
                splunk_idx = "sfo-pn2-spidx01.pn1.ci.lan"
            elif splunk_idx_no == "2":
                splunk_idx = "sfo-pn2-spidx02.pn1.ci.lan"
            splunk_colo = "pn2"
        else:
            print("Please provide the right option.")
            logging.warning('Selecting Wrong option while using the script')
            print()
            return

        logging.info(f'{name} has selected splunk cluster is: %s' % splunk_colo)
        logging.info(f'{name} has selected splunk indexer is: %s' % splunk_idx)

        #splunk_list = ['mariadb', 'static', 'cprgw', 'rcpt', 'cassandra', 'apache-cassandra', 'cep', 'rst', 'rstc', 'rsts', 'react', 'hornetq', 'ngw', 'wsrt', 'ci-zookeeper-pem', 'nre', 'uxm', 'uxmt', 'uxnd', 'widgets', 'uxhc', 'pai', 'pai-prd', 'gemfire', 'geode', 'akka', 'sched', 'lv1-rebuild', 'sc5-rebuild', 'mblmt', 'cpr', 'nrecs', 'kafka', 'kafkacon', 'cpa-pai', 'qbi', 'campaigns', 'merch', 'moriq', 'amq', 'pem', 'varnish', 'batch', 'batch', 'foursquare', 'appboy', 'redis', 'dse', 'qem']

        #splunk_input_list = ['mariadb', 'static', 'cprgw', 'rcpt', 'cassandra', 'apache-cassandra', 'cep', 'rst', 'rstc', 'rsts', 'react', 'hornetq', 'ngw', 'wsrt', 'ci-zookeeper-pem', 'nre', 'uxm', 'uxmt', 'uxnd', 'widgets', 'uxhc', 'pai', 'pai-prd', 'gemfire', 'geode', 'akka', 'sched', 'lv1-rebuild', 'sc5-rebuild', 'mblmt', 'cpr', 'nrecs', 'kafka', 'kafkacon', 'cpa-pai', 'qbi', 'campaigns', 'merch', 'moriq', 'amq', 'pem', 'varnish', 'batch', 'batch', 'foursquare', 'appboy', 'redis', 'dse', 'qem', 'ccutl', 'cms', 'ci-adcaster', 'ci-batch', 'ci-bcacl', 'ci-bcpub', 'ci-varnish', 'dreamhouse', 'ci-blog', 'ci-corpsite', 'ci-cpr', 'ci-mtc', 'ci-gemfire', 'ci-gemfiregw', 'ci-sso', 'ci-ssolr', 'ci-ccsolr', 'ci-ccweb-geo', 'ci-bcbcn', 'ci-redis', 'ci-ccrds', 'ci-ccweb', 'ci-web', 'ci-soc', 'ci-bcn', 'ci-ukcpr', 'listdb', 'ci-rssfeed', 'ci-hub', 'ci-cliq', 'ci-adb', 'ci-dst', 'pai-mysql', 'pai', 'pai-prd', 'ci-kafkacon', 'ci-kafka-pem', 'ci-static', 'ci-jarvis', 'ci-zookeeper-pem', 'ci-dts', 'bi-mstr', 'bi-mstrdss', 'azure-bi', 'ci-geo', 'ci-bcapi', 'solr']

        # Create chunks of data for each column
        num_columns = 6
        chunked_data = [SPLUNK_LIST[i:i + num_columns] for i in range(0, len(SPLUNK_LIST), num_columns)]

        # Fill shorter chunks with empty strings to align columns
        max_length = max(len(chunk) for chunk in chunked_data)
        for chunk in chunked_data:
            chunk.extend([''] * (max_length - len(chunk)))

        # Transpose the data for tabulation
        transposed_data = list(map(list, zip(*chunked_data)))

        # Print the tabulated data without headers
        table = tabulate(transposed_data, tablefmt='grid', headers=[])
        print(table)
        splunk_host = input("Please provide the splunk hosts component from the above table: ").lower()
        logging.info(f'{name} has selected splunk hosts type is: %s' % splunk_host)

        if not splunk_host:
            print("\n")
            print("Input is blank. Please try again.")
            logging.warning('User has not selected any "Splunk-Hosts"')
            print("\n")
            return

        complex_hosts = []
        for HOSTNAME, ip_address in zip(HOSTNAMES, hosts):
            complex_host = f"{HOSTNAME} ansible_ssh_host={ip_address} idx={splunk_idx} colo={splunk_colo}"
            complex_hosts.append(complex_host)

        # Write the complex host entries to the output file
        with open(f"{HOST_FILE}", "w") as f:
            f.write("\n".join(complex_hosts) + "\n")

        # Add the new line at the start of the file
        file_modify = f"{HOST_FILE}"
        new_word_add = f"[{splunk_host}]" + '\n'
        prepend_word(file_modify, new_word_add)

        # Add the some line for putting app-input files.
        for item in SPLUNK_INPUT_LIST:
            if item != splunk_host:
                store = item
            input_file_modify = f"{HOST_FILE}"
            new_line_add = f"[{store}]"
            append_line(input_file_modify, new_line_add)
        ###############################################

        #change the Directory
        os.chdir(PATH)

        #running command in specific directory
        splunk_command = f"ansible-playbook -i {HOST_FILE} -e 'hosts={splunk_host}' --limit={limit_host} {PATH}/{SPLUNK} --ask-pass"
        #print(f"Running Ansible command: {ansible_command}")
        logging.info(f'Running Command: {splunk_command}')
        result = run_subprocess(splunk_command)

        # Remove the new line at the start of the file
        remove_word(file_modify, new_word_add)
        for item in SPLUNK_INPUT_LIST:
            if item != splunk_host:
                store = item.strip()
            input_file_modify = f"{HOST_FILE}"
            new_line_add = f"[{store}]" + '\n'
            remove_word(input_file_modify, new_line_add)

        return result
    
    except KeyboardInterrupt:
        print("\n")
        print("\nScript terminated by user.")
        logging.warning('Script is terminated by user')
        logging.info('')
        logging.info('==========================> ENDED <===========================')
        sys.exit(1)

if __name__ == '__main__':
    args = parse_arguments()
    user_detail()
    main()
    logging.info('==========================> ENDED <===========================')

#Ended the script