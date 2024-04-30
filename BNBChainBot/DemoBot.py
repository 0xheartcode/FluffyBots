import logging
import time
import os
import sys
import traceback
import requests
import json
import warnings

from decimal import Decimal
from datetime import datetime
from web3.exceptions import ValidationError
from dotenv import load_dotenv
from telegram import Update, BotCommand
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
from web3 import Web3
from web3.utils.address import to_checksum_address

load_dotenv()
# Set up logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)


# Initialize web3 provider (e.g., connect to BSC mainnet)
web3 = Web3(Web3.HTTPProvider('https://bscrpc.com'))
# web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545/'))

# Telegram bot token
TOKEN = os.environ.get('TOKEN')
# Set your Etherscan API key
bscscan_api_key = os.environ.get('BSCSCAN_API')
 
# Initialize the bot
updater = Updater(token=TOKEN, use_context=True)
dispatcher = updater.dispatcher

# Admin list
initial_admin = os.environ.get('ADMIN')
second_admin = os.environ.get('ADMIN_TWO')
admin_list = [initial_admin]  # List of initial admin usernames
admin_list.append(second_admin)
logging.info(admin_list)
# Private key list
private_keys = []
tokens = []

# Error handler function
def error_handler(update: Update, context: CallbackContext) -> None:
    logging.error(f"Exception occurred: {context.error}")
    context.bot.send_message(chat_id=update.effective_chat.id, text="An error occurred. Please try again later.")


# Handler function for /start command
def start(update: Update, context: CallbackContext) -> None:
    filename = os.path.basename(sys.argv[0])
    context.bot.send_message(chat_id=update.effective_chat.id, text=f'Hi, I am your bot {filename}. Send me a message!')


BOT_VERSION = '1.0.0'
def version(update: Update, context: CallbackContext) -> None:
    filename = os.path.basename(sys.argv[0])
    file_path = os.path.join(os.getcwd(), filename)
    modified_time = os.path.getmtime(file_path)
    last_modified_date = datetime.fromtimestamp(modified_time).strftime('%Y-%m-%d')
    context.bot.send_message(chat_id=update.effective_chat.id, text=f'Hi, I am your bot {filename}.\n Bot version {BOT_VERSION}\n Released on the {last_modified_date}')


# Handler function and variable for slippage

slippage = float(30)

def get_slippage(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() not in admin_list:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')
        return

    context.bot.send_message(chat_id=update.effective_chat.id, text=f'Slippage set to {slippage}')

def set_slippage(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() not in admin_list:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')
        return

    global slippage
    args = update.message.text.split()[1:]
    if len(args) != 1:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /set_slippage value')
        return
    
    try:
        new_slippage = int(args[0])
        if new_slippage < 1 or new_slippage > 70:
            context.bot.send_message(chat_id=update.effective_chat.id, text='Slippage value must be between 1 and 70.')
            return
        new_slippage = float(new_slippage)
        slippage = new_slippage
        context.bot.send_message(chat_id=update.effective_chat.id, text=f'Slippage set to {slippage}')
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid slippage value. Please provide a valid integer.')
        return
# Handler function for /addadmin command
def add_admin(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() in admin_list:
        if len(update.message.text.split()) <= 1:
            context.bot.send_message(chat_id=update.effective_chat.id, text='Please provide a username after the command.')
            return

        username_with_prefix = update.message.text.split()[1]  # Get the username from the command
        username = extract_username(username_with_prefix)  # Extract username without prefix
        if username and username not in admin_list:
            admin_list.append(username)
            context.bot.send_message(chat_id=update.effective_chat.id, text=f'Added {username} as admin.')
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text=f'{username} is already an admin.')
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')

# Extract username without prefixes
def extract_username(username_with_prefix: str) -> str:
    prefixes = ['@', 'https://t.me/', 't.me/']
    username = username_with_prefix.lower().strip()
    for prefix in prefixes:
        if username.startswith(prefix):
            username = username[len(prefix):]
            break
    return username


# Handler function for /removeadmin command

def remove_admin(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() in admin_list:
        if len(update.message.text.split()) < 2:
            context.bot.send_message(chat_id=update.effective_chat.id, text='No username provided. Usage: /remove_admin <username>')
            return
        
        username_with_prefix = update.message.text.split()[1]  # Get the username from the command
        username = extract_username(username_with_prefix)  # Extract username without prefix
        
        if username in admin_list and username != 'username':
            admin_list.remove(username)
            context.bot.send_message(chat_id=update.effective_chat.id, text=f'Removed {username} from admins.')
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text=f'{username} is not an admin or cannot be removed.')
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')

# Handler function for /listadmins command
def list_admins(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.username.lower() in admin_list:
        admins = "\n".join([f"@{admin}" for admin in admin_list])
        context.bot.send_message(chat_id=update.effective_chat.id, text=f'List of admins:\n{admins}')
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')


# Handler function for /help command
def help_command(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() in admin_list:
        if update.message.chat.type != 'private':
            context.bot.send_message(chat_id=update.effective_chat.id, text='For admins, this command can only be used in DMs.')
            return

        commands = [
            BotCommand('/start', 'Start the bot'), #All, all
            BotCommand('/help', 'Display available commands'), #All, all
            BotCommand('/addadmin', '<admin> - Add a user as admin'), #Admin, in DMs
            BotCommand('/removeadmin', '<admin> - Remove a user from admins'), #Admin, in DMs
            BotCommand('/listadmins', 'List all admins'), #Admin, in DMs
            BotCommand('/add_privatekey', '<key> <tag> - Add a private key with a tag'), #Admin,in DMs
            BotCommand('/remove_privatekey', '<tag> - Remove a private key by its tag'),#Admin,in DMs
            BotCommand('/list_privatekeys', '- List all private keys'),#Admin, in DMs
            BotCommand('/edit_privatekey', '<tag> <key> - Edit a specific tag'),#Admin, in DMs
            BotCommand('/set_slippage', 'Set the default slippage'),#Admin, in DMs 
            BotCommand('/get_slippage', 'Get the default slippage'),#Admin, in DMs   
            BotCommand('/list_wallets', 'list_wallets'),#Admin, in DMs
            BotCommand('/gas_prices', 'Show gas prices'), #All, all
            BotCommand('/bnb_price', 'Show the current price of bnb'), #All, all
            BotCommand('/setup','easy setup to get started, imports privatekeys.'),#Admin, in DMs
            BotCommand('/listwallet_balances','lists the balances of the wallets'),#Admin, in DMs
            BotCommand('/version','Information about the current version'),#All, all
            
            BotCommand('/send_bnb','send_bnb'), #Admin, all 
            BotCommand('/buy','<amount> <token_address> - buy BEP20 token with USDT'),#All, all
            BotCommand('/buy_standard','<amount> <token_address> - buy BEP20 token with BNB'),
            BotCommand('/sell','<amount> <token_address> - sell BEP20 token with USDT'),#All, all
            BotCommand('/sell_standard','<amount> <token_address> - sell BEP20 token with BNB'),#All, all
            BotCommand('/transfer','<amount> <receiver_address> <token_address> - send token from 1 wallet to another'), #All, all

            BotCommand('/add_token','Add a token to the list of valid tokens'),#Admin, all
            BotCommand('/list_tokens','List all valid tokens'),#All, all
            BotCommand('/remove_token','Remove a token from the list of valid tokens')#Admin, all
        ]
    else:
        commands = [
            BotCommand('/start', 'Start the bot'),
            BotCommand('/help', 'Display available commands'),
            BotCommand('/gas_prices', 'Show gas prices'), #All, all
            BotCommand('/bnb_price', 'Show the current price of bnb'), #All, all
            BotCommand('/version','Information about the current version'),#All, all
            BotCommand('/buy','<amount> <token_address> - buy BEP20 token with USDT'),#All, all
            BotCommand('/sell','<amount> <token_address> - sell BEP20 token with USDT'),#All, all
            BotCommand('/transfer','<amount> <receiver_address> <token_address> - send token from 1 wallet to another'),#All, all
            BotCommand('/list_tokens','List all valid tokens')#All, all
 
        ]

    context.bot.set_my_commands(commands)

    help_text = "Available commands:\n\n" + "\n".join([f"{command.command} - {command.description}" for command in commands])
    context.bot.send_message(chat_id=update.effective_chat.id, text=help_text)

# Example usage:
def setup(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() not in admin_list:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')
        return

    private_keys.append((os.environ.get('PRIVATEKEY_WALLET1'), 'Wallet1'))
    context.bot.send_message(chat_id=update.effective_chat.id, text=f'Private key added with tag: Wallet1')

# Handler function for /add_privatekey command

def add_privatekey(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.username.lower() in admin_list:
        args = update.message.text.split()[1:]
        if len(args) == 2:
            key = args[0]
            tag = args[1]

            # Validate the private key
            is_valid_private_key = is_valid_key(key)
            if is_valid_private_key:
                private_keys.append((key, tag))
                context.bot.send_message(chat_id=update.effective_chat.id, text=f'Private key added with tag: {tag}')
            else:
                context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid private key.')
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /add_privatekey <key> <tag>')
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')

def is_valid_key(private_key: str) -> bool:
    try:
        account = web3.eth.account.from_key(private_key)
        return True
    except ValueError:
        return False

# Handler function for /remove_privatekey command

def remove_privatekey(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.username.lower() in admin_list:
        args = update.message.text.split()[1:]
        if len(args) >= 1:
            tag = args[0]
            removed_keys = []
            for key, key_tag in private_keys:
                if key_tag == tag:
                    private_keys.remove((key, key_tag))
                    removed_keys.append(key_tag)
            if removed_keys:
                removed_keys_str = ", ".join(removed_keys)
                context.bot.send_message(chat_id=update.effective_chat.id, text=f'Removed private key(s) with tag: {removed_keys_str}')
            else:
                context.bot.send_message(chat_id=update.effective_chat.id, text=f'No private keys found with tag: {tag}')
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /remove_privatekey <tag>')
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')

# Handler function for /list_privatekeys command
def list_privatekeys(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.username.lower() in admin_list:
        if private_keys:
            private_keys_str = "\n".join([f"{tag}: {key}" for key, tag in private_keys])
            context.bot.send_message(chat_id=update.effective_chat.id, text=f'List of private keys:\n{private_keys_str}')
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text='No private keys found.')
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')


def edit_privatekey(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.username.lower() in admin_list:
        args = update.message.text.split()[1:]  # Get the arguments from the command (excluding the command itself)
        if len(args) == 2:
            tag = args[0]
            new_key = args[1]
            # Validate the private key
            is_valid_private_key = is_valid_key(new_key)
            if not is_valid_private_key:
                context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid private key.')
                return
 
            for i, (key, existing_tag) in enumerate(private_keys):
                if existing_tag == tag:
                    private_keys[i] = (new_key, tag)
                    context.bot.send_message(chat_id=update.effective_chat.id, text=f"Private key for tag '{tag}' has been updated.")
                    break
                else:
                    context.bot.send_message(chat_id=update.effective_chat.id, text=f"Tag '{tag}' does not exist.")
            else:
                context.bot.send_message(chat_id=update.effective_chat.id, text=f"Tag '{tag}' is not a valid private key tag.")
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="Invalid number of arguments. Usage: /edit_privatekey <tag> <newkey>")
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')


# Function to get wallet address from private key
def get_address(private_key):
    return web3.eth.account.from_key(private_key).address


# Handler function for /list_wallets command
def list_wallets(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.username.lower() in admin_list:
        if private_keys:
            response = "List of wallet addresses:\n\n"
            for key, tag in private_keys:
                address = get_address(key)
                response += f"Tag: {tag}\nAddress: {address}\n\n"
            context.bot.send_message(chat_id=update.effective_chat.id, text=response)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text='No private keys found.')
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')

def gas_prices(update: Update, context: CallbackContext) -> None:
    try:
       
        # API endpoint to fetch gas price
        api_url = f"https://api.bscscan.com/api?module=gastracker&action=gasoracle&apikey={bscscan_api_key}"
        
        # Make an HTTP request to fetch gas price data
        response = requests.get(api_url)
        data = response.json()
        
        # Check if the request was successful
        if data['status'] == '1':
            result = data['result']
            
            average_gas_price = result['SafeGasPrice']
            min_gas_price = result['ProposeGasPrice']
            max_gas_price = result['FastGasPrice']
            
            message = f"Gas Prices:\nAverage: {average_gas_price} gwei\nLow: {min_gas_price} gwei\nHigh: {max_gas_price} gwei"
            
            context.bot.send_message(chat_id=update.effective_chat.id, text=message)
        else:
            error_message = f"An error occurred: {data['message']}"
            context.bot.send_message(chat_id=update.effective_chat.id, text=error_message)
    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        traceback.print_exc()
        context.bot.send_message(chat_id=update.effective_chat.id, text=error_message)

def bnb_price(update: Update, context: CallbackContext) -> None:
    # Add debug statements in your code
    try:
        
        # API endpoint to fetch BNB price
        api_url = f"https://api.bscscan.com/api?module=stats&action=bnbprice&apikey={bscscan_api_key}"
        
        # Make an HTTP request to fetch BNB price data
        response = requests.get(api_url)
        data = response.json()
        
        # Check if the request was successful
        if data['status'] == '1':
            result = data['result']
            bnb_price = result['ethusd']
            
            message = f"Current BNB Price: {bnb_price} USD"
            
            context.bot.send_message(chat_id=update.effective_chat.id, text=message)
        else:
            error_message = f"An error occurred: {data['message']}"
            context.bot.send_message(chat_id=update.effective_chat.id, text=error_message)
    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        traceback.print_exc()
        context.bot.send_message(chat_id=update.effective_chat.id, text=error_message)


def listwallet_balances(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() not in admin_list:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')
        return

    balances = {}

    if not private_keys:
        context.bot.send_message(chat_id=update.effective_chat.id, text="No wallet has been added.")
        return

    token_abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeERC20.sol/PancakeERC20.json"

    response_token = requests.get(token_abi_url)
    token_abi_data = response_token.json()
    token_abi = token_abi_data



    usdt_address = "0x55d398326f99059fF775485246999027B3197955"
    usdt_contract = web3.eth.contract(address=Web3.to_checksum_address(usdt_address), abi=token_abi)

    for private_key, tag in private_keys:
        account = web3.eth.account.from_key(private_key)
        address = account.address

        balance_wei = web3.eth.get_balance(address)
        balance_eth = web3.from_wei(balance_wei, 'ether')
        balance_eth = round(balance_eth, 4)
        balance_eth = str(balance_eth).rstrip('0').rstrip('.')

        balance_usdt = usdt_contract.functions.balanceOf(address).call()
        decimals = usdt_contract.functions.decimals().call()
        balance_usdt_readable = balance_usdt / 10**decimals
        balance_usdt_edit = round(balance_usdt_readable, 4)
        balance_usdt_formatted = str(balance_usdt_edit).rstrip('0').rstrip('.') 


        balances[tag] = {
            "BNB": balance_eth,
            "USDT": balance_usdt_formatted
        }

    message = "Wallet Balances:\n"

    for tag, balances in balances.items():
        message += f"{tag}: {balances['BNB']} BNB | {balances['USDT']} USDT\n"

    context.bot.send_message(chat_id=update.effective_chat.id, text=message)

def get_average_gas_price() -> int:
    api_url = f"https://api.bscscan.com/api?module=gastracker&action=gasoracle&apikey={bscscan_api_key}"

    response = requests.get(api_url)
    data = response.json()

    if data['status'] == '1':
        result = data['result']
        average_gas_price = int(result['SafeGasPrice'])
        return average_gas_price
    else:
        # Handle API error
        raise Exception(f"Failed to fetch average gas price: {data['message']}")


def transfer(update: Update, context: CallbackContext) -> None:
    args = update.message.text.split()[1:]
    if len(args) != 3:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /transfer amount wallet2Address tokenAddress')
        return
    try:
        amount = float(args[0])
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid amount. Please provide a valid number.')
        return

    # Privatekey check, for main wallet

    wallet1_private_key = None

    if not private_keys:
        context.bot.send_message(chat_id=update.effective_chat.id, text='No private keys found. Please add a wallet first.')
        return

    wallet1_private_key = private_keys[0][0]

    wallet1_account = web3.eth.account.from_key(wallet1_private_key)
    wallet1_address = wallet1_account.address


 
    ## CONTINUE HERE
    
    receiver_address = args[1]
    try:
        receiver_address = Web3.to_checksum_address(receiver_address)
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Receiver address checksum failed. Have you put in the correct address?')
        return

    wallet2_address = receiver_address

    ## check if code exists at address that has been defined
    raw_token_address = args[2]
    try:
        token_address = Web3.to_checksum_address(raw_token_address)
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Checksum failed. Have you put in the correct address?')
        return

    token_code = web3.eth.get_code(token_address)
    if token_code == b'':
        context.bot.send_message(chat_id=update.effective_chat.id, text='No code exists at the specified address')
        return

    # Check if the provided token address is in the tokens list
    token = next((t for t in tokens if t[0] == token_address), None)
    if token is None:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid token address. Please provide a token address that is added using the /add_token command.')
        return

    average_gas_price = get_average_gas_price()
    ## instantiate contract abi
    token_abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeERC20.sol/PancakeERC20.json"

    response_token = requests.get(token_abi_url)
    token_abi_data = response_token.json()
    token_abi = token_abi_data

    token_contract = web3.eth.contract(address=token_address, abi=token_abi)

    walletbalance_oftoken = token_contract.functions.balanceOf(wallet1_address).call()
    walletbalance_oftoken = web3.from_wei(walletbalance_oftoken, 'ether')
    # check if '_amount' is bigger than wallet1 has balance of the token
    if walletbalance_oftoken < amount:
        context.bot.send_message(chat_id=update.effective_chat.id, text=f'Wallet balance: {walletbalance_oftoken}.\n Amount to transfer: {amount}. \nYou need a positive balance.')
        return
    
    ## do the transfer
    try:
        transaction = token_contract.functions.transfer(receiver_address, int(amount * 10**18)).build_transaction({
            'from': wallet1_address,
            'gas': 100000,
            'gasPrice': web3.to_wei(average_gas_price, 'gwei'),
            'nonce': web3.eth.get_transaction_count(wallet1_address)
        })
        signed_txn = web3.eth.account.sign_transaction(transaction, private_key=wallet1_private_key)
        transaction_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        transaction_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)

        if transaction_receipt.status == 1:
            tx_hash = transaction_hash.hex()
            tx_hash_short = tx_hash[:4] + "..." + tx_hash[-4:]
            wallet1_address_short = wallet1_address[:4]+"..." + wallet1_address[-4:]
            wallet2_address_short = wallet2_address[:4]+"..." + wallet2_address[-4:]
            bscscan_url = f"https://bscscan.com/tx/{tx_hash}"
            bscscan_sender = f"https://bscscan.com/address/{wallet1_address}"
            bscscan_receiver = f"https://bscscan.com/address/{wallet2_address}" 

            if amount < 0.00001:
                amount_text = f"<0.00001"
            else:
                amount_text = f"{amount:.5f}"

            success_message = f"Successfully sent {amount_text} TOKEN from\n [{wallet1_address_short}]({bscscan_url}) to [{wallet2_address_short}]({bscscan_receiver}).\nTx hash: [{tx_hash_short}]({bscscan_url})"
            context.bot.send_message(chat_id=update.effective_chat.id, text=success_message, parse_mode='Markdown', disable_web_page_preview=True)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text=f"Transaction failed.")

    except Exception as e:
        error_message = str(e)

        if "insufficient funds" in error_message.lower():
            error_message = "Insufficient funds in the sender's account."
            context.bot.send_message(chat_id=update.effective_chat.id, text=error_message)
            return

        # Handle other exceptions
        error_message = f"An error occurred: {str(e)}"
        context.bot.send_message(chat_id=update.effective_chat.id, text=error_message)


def send_bnb(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() not in admin_list:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')
        return


    # Extract the arguments from the user input
    args = update.message.text.split()[1:]
    if len(args) != 2:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /send_bnb amount wallet2address')
        return
    # Parse the amount and wallet tags
    try:
        amount = float(args[0])
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid amount. Please provide a valid number.')
        return

    receiver_address = args[1]
    
    # Fetch the private key
    wallet1_private_key = None

    if not private_keys:
        context.bot.send_message(chat_id=update.effective_chat.id, text='No private keys found. Please add a wallet first.')
        return

    wallet1_private_key = private_keys[0][0]
    
    try:
        receiver_address = Web3.to_checksum_address(receiver_address)
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Receiver address checksum failed. Have you put in the correct address?')
        return

    wallet1_account = web3.eth.account.from_key(wallet1_private_key)
    wallet1_address = wallet1_account.address

    wallet2_address = receiver_address

    true_average_gas_price = get_average_gas_price()

    transaction = {
        'from': wallet1_address,
        'to': wallet2_address,
        'value': web3.to_wei(amount, 'ether'),
        'gas': 21000,  # Gas limit for a standard BNB transfer
        'gasPrice': web3.to_wei(true_average_gas_price,'gwei'),
        'chainId': 56,  
        'nonce': web3.eth.get_transaction_count(wallet1_address)
    }

    try:
        signed_transaction = wallet1_account.sign_transaction(transaction)
        transaction_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        transaction_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)

        if transaction_receipt.status == 1:
            tx_hash = transaction_hash.hex()
            tx_hash_short = tx_hash[:4] + "..." + tx_hash[-4:]
            wallet1_address_short = wallet1_address[:4]+"..." + wallet1_address[-4:]
            wallet2_address_short = wallet2_address[:4]+"..." + wallet2_address[-4:]
            bscscan_url = f"https://bscscan.com/tx/{tx_hash}"
            bscscan_sender = f"https://bscscan.com/address/{wallet1_address}"
            bscscan_receiver = f"https://bscscan.com/address/{wallet2_address}" 

            if amount < 0.00001:
                amount_text = f"<0.00001"
            else:
                amount_text = f"{amount:.5f}"
            
            success_message = f"Successfully sent {amount_text} BNB from\n [{wallet1_address_short}]({bscscan_sender}) to [{wallet2_address_short}]({bscscan_receiver}).\nTx hash: [{tx_hash_short}]({bscscan_url})"
            context.bot.send_message(chat_id=update.effective_chat.id, text=success_message, parse_mode='Markdown', disable_web_page_preview=True)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text=f"Transaction failed.")

    except Exception as e:
        error_message = str(e)

        if "insufficient funds" in error_message.lower():
            error_message = "Insufficient funds in the sender's account."
            context.bot.send_message(chat_id=update.effective_chat.id, text=error_message)
            return

        # Handle other exceptions
        error_message = f"An error occurred: {str(e)}"
        context.bot.send_message(chat_id=update.effective_chat.id, text=error_message)



    # Extract the arguments from the user input
    args = update.message.text.split()[1:]
    if len(args) != 2:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /buy amount tokenAddress')
        return
    
    # Parse the amount and wallet tag
    try:
        amount = float(args[0])
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid amount. Please provide a valid number.')
        return
    
    cake_contract_address = args[1]

    wallet1_private_key = None

    if not private_keys:
        context.bot.send_message(chat_id=update.effective_chat.id, text='No private keys found. Please add a wallet first.')
        return

    wallet1_private_key = private_keys[0][0]
    
    try:
        receiver_address = Web3.to_checksum_address(cake_contract_address)
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Token address checksum failed. Have you put in the correct address?')
        return
    # Check if the provided token address is in the tokens list
    token = next((t for t in tokens if t[0] == receiver_address), None)
    if token is None:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid token address. Please provide a token address that is added using the /add_token command.')
        return

    wallet1_account = web3.eth.account.from_key(wallet1_private_key)
    wallet1_address = wallet1_account.address

    
    
    # URL of the ABI JSON file on GitHub
    abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeRouter.sol/PancakeRouter.json" 
    # Fetch the contents of the ABI JSON file
    response = requests.get(abi_url)
    abi_data = response.json()
    # Extract the ABI from the JSON data
    pancake_router_abi = abi_data

    token_abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeERC20.sol/PancakeERC20.json"

    response_token = requests.get(token_abi_url)
    token_abi_data = response_token.json()
    token_abi = token_abi_data

    # Perform the swap on PancakeSwap v2
    try:
        router_address = '0x10ED43C718714eb63d5aA57B78B54704E256024E'  # Address of the PancakeSwap router
        bnb_token = Web3.to_checksum_address('0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c')  # Address of BNB token
        cake_contract_address = Web3.to_checksum_address(cake_contract_address)  # Address of token

        pancake_router = web3.eth.contract(address=router_address, abi=pancake_router_abi)
        token_contract = web3.eth.contract(address=cake_contract_address, abi= token_abi)
        token_symbol = token_contract.functions.symbol().call()
        wallet1_account = web3.eth.account.from_key(wallet1_private_key)
        wallet1_address = wallet1_account.address
        
        deadline = int(time.time()) + 60  # Set deadline 1 minutes from now

        path = [bnb_token, cake_contract_address]
        # Get the amount of CAKE that will be received
        amounts = pancake_router.functions.getAmountsOut(Web3.to_wei(amount, 'ether'), path).call()
        
        try: 
            decimals = token_contract.functions.decimals().call()
            logging.info("Decimals for this token: " + str(decimals))
        except Exception as e:
            logging.info("Could not fetch contract decimals. Defaulting to 18. Contact Dev for help.")
        
        cake_amount = Web3.from_wei(amounts[1], 'ether')
        # cake_amount = Web3.from_wei(amounts[-1], 'ether')
        amount_percentage = float(slippage / 100)
        amount_neg = amounts[1] * amount_percentage
        amount_out_min = amounts[1] - amount_neg
        amount_out_min = int(amount_out_min)
        # amount_out_min = float(amount_out_min)
        average_gas_price = get_average_gas_price()

        transaction = pancake_router.functions.swapExactETHForTokensSupportingFeeOnTransferTokens(
            amount_out_min,   # amountOutMin
            path,
            wallet1_address,
            deadline
        ).build_transaction({
            'from': wallet1_address,
            'value': Web3.to_wei(amount, 'ether'),
            'gas': 300000,
            'gasPrice': web3.to_wei(average_gas_price, 'gwei'),
            'nonce': web3.eth.get_transaction_count(wallet1_address),
            # 'deadline': deadline
        })
    
        # Sign the transaction
        signed_transaction = web3.eth.account.sign_transaction(transaction, private_key=wallet1_private_key)

        # Send the raw transaction
        transaction_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        messageInProgress = context.bot.send_message(chat_id=update.effective_chat.id, text='Sending transaction... <o.o>')

        # logging.info("Everything okay until here ! Line 744 good. Let's start debugging !")
        # Wait for the transaction receipt
        transaction_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
                  
        context.bot.delete_message(chat_id=update.effective_chat.id, message_id=messageInProgress.message_id)
        if transaction_receipt.status == 1:
            basicEvent = token_contract.events.Transfer()

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                events = token_contract.events.Transfer().process_receipt(transaction_receipt)
            amount_sent = 0
            amount_received = 0

            if events: # If there are multiple 'Transfer' events, you can iterate over them to calculate the total amount sent and received
                for event in events:
                    if event['args']['to'] == wallet1_address:
                        amount_received += event['args']['value']
                    # Log the amount sent and received
            if decimals == 0:
                decimals = 18
            
            amount_received_formatted = (amount_received / 10 ** decimals)
            cake_amount = amount_received_formatted

            tx_hash = transaction_hash.hex()
            tx_hash_short = tx_hash[:4] + "..." + tx_hash[-4:]
            bscscan_url = f"https://bscscan.com/tx/{tx_hash}" 
            sent_url = f"https://bscscan.com/token/{bnb_token}"
            received_url = f"https://bscscan.com/token/{cake_contract_address}" 
            
            if cake_amount < 0.0001:
                cake_amount_formated = f"<0.0001"
            else:
                cake_amount_formated = f"{round(cake_amount, 4):.4f}".rstrip("0").rstrip(".")


            if amount < 0.0001:
                amount_formated = f'<0.0001'
            else:
                amount_formated = f"{round(amount, 4):.4f}".rstrip("0").rstrip(".")
            
            message = f"Successfully bought {cake_amount_formated} [{token_symbol}]({received_url}) for {amount_formated} [BNB]({sent_url}).\n"
            message += f"Tx hash: [{tx_hash_short}]({bscscan_url})\n"
            
            context.bot.send_message(chat_id=update.effective_chat.id, text=message, parse_mode='Markdown', disable_web_page_preview=True)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="Swap transaction failed.")
    except Exception as e:
        traceback.print_exc()
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"An error occurred: {str(e)}")



def buy(update: Update, context: CallbackContext) -> None:

    # Extract the arguments from the user input
    args = update.message.text.split()[1:]
    if len(args) != 2:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /buy amount tokenAddress')
        return
    
    # Parse the amount and wallet tag
    try:
        amount = float(args[0])
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid amount. Please provide a valid number.')
        return
    
    cake_contract_address = args[1]

    wallet1_private_key = None

    if not private_keys:
        context.bot.send_message(chat_id=update.effective_chat.id, text='No private keys found. Please add a wallet first.')
        return

    wallet1_private_key = private_keys[0][0]
    
    try:
        receiver_address = Web3.to_checksum_address(cake_contract_address)
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Token address checksum failed. Have you put in the correct address?')
        return
    # Check if the provided token address is in the tokens list
    token = next((t for t in tokens if t[0] == receiver_address), None)
    if token is None:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid token address. Please provide a token address that is added using the /add_token command.')
        return

    wallet1_account = web3.eth.account.from_key(wallet1_private_key)
    wallet1_address = wallet1_account.address

    
    
    # URL of the ABI JSON file on GitHub
    abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeRouter.sol/PancakeRouter.json" 
    # Fetch the contents of the ABI JSON file
    response = requests.get(abi_url)
    abi_data = response.json()
    # Extract the ABI from the JSON data
    pancake_router_abi = abi_data

    token_abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeERC20.sol/PancakeERC20.json"

    response_token = requests.get(token_abi_url)
    token_abi_data = response_token.json()
    token_abi = token_abi_data

    try: 
        usdt_token_address = Web3.to_checksum_address('0x55d398326f99059fF775485246999027B3197955')
        usdt_contract = web3.eth.contract(address=usdt_token_address, abi=token_abi)
    except Exception as e:
        traceback.print_exc()
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"An error occurred: {str(e)}")

    usdt_balance = usdt_contract.functions.balanceOf(wallet1_address).call()
    amount_in_wei = Web3.to_wei(amount, 'ether')
    if usdt_balance < amount_in_wei:
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"Insufficient USDT balance.")
        return

    logging.info('USDT_balance: ' + str(usdt_balance))
    logging.info("Amount in wei: " + str(amount_in_wei))


    # Perform the swap on PancakeSwap v2
    try:
        router_address = '0x10ED43C718714eb63d5aA57B78B54704E256024E'  # Address of the PancakeSwap router
        bnb_token = Web3.to_checksum_address('0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c')  # Address of BNB token
        cake_contract_address = Web3.to_checksum_address(cake_contract_address)  # Address of token

        pancake_router = web3.eth.contract(address=router_address, abi=pancake_router_abi)
        token_contract = web3.eth.contract(address=cake_contract_address, abi= token_abi)
        token_symbol = token_contract.functions.symbol().call()
        wallet1_account = web3.eth.account.from_key(wallet1_private_key)
        wallet1_address = wallet1_account.address
        
        deadline = int(time.time()) + 60  # Set deadline 1 minutes from now

        path = []
        amounts = []
        # Get the amount of TOKEN that will be received
        try: 
            decimals = token_contract.functions.decimals().call()
        except Exception as e:
            logging.info("Could not fetch contract decimals. Defaulting to 18. Contact Dev for help.")
            decimals = 18

        amount_cleaned = int(amount * 10**decimals)
        try:
            path = [usdt_token_address, bnb_token , cake_contract_address]
            amounts = pancake_router.functions.getAmountsOut(amount_cleaned, path).call()
        except Exception as e:
            try:
                logging.info('TOKEN/BNB PATH not found. Looking for TOKEN/USDT PATH...')
                path = [usdt_token_address, cake_contract_address]
                amounts = pancake_router.functions.getAmountsOut(amount_cleaned, path).call()
            except Exception as e:
                logging.info("No path was found. Contact Dev for help.")
                traceback.print_exc()
                context.bot.send_message(chat_id=update.effective_chat.id, text=f"An error occurred: {str(e)}")

                return

        average_gas_price = get_average_gas_price()
        #APPROVAL CHECK
        current_allowance = usdt_contract.functions.allowance(wallet1_address, router_address).call()
        
        if current_allowance < amounts[0]:

            max_approval_amount = 10 ** decimals - 1

            # Approve the spending of tokens by the router contract
            approve_tx = usdt_contract.functions.approve(router_address, max_approval_amount).build_transaction({
                'from': wallet1_address,
                'gas': 200000,
                'gasPrice': web3.to_wei(average_gas_price, 'gwei'),
                'nonce': web3.eth.get_transaction_count(wallet1_address)
            })

            signed_approve_txn = web3.eth.account.sign_transaction(approve_tx, private_key=wallet1_private_key)
            approve_tx_hash = web3.eth.send_raw_transaction(signed_approve_txn.rawTransaction)
            approve_tx_receipt = web3.eth.wait_for_transaction_receipt(approve_tx_hash)

            if approve_tx_receipt['status'] == 1:
                logging.info("Token approval successful")
            else:
                logging.error("Token approval failed")# Approve the spending of tokens by the router contract
        # ... (approval step)
        else:
            logging.info("Sufficient allowance already granted")



        cake_amount = Web3.from_wei(amounts[-1], 'ether')
        # cake_amount = Web3.from_wei(amounts[-1], 'ether')
        amount_percentage = float(slippage / 100)
        amount_neg = amounts[-1] * amount_percentage
        amount_out_min = amounts[-1] - amount_neg
        amount_out_min = int(amount_out_min)
        # amount_out_min = float(amount_out_min)
        
        logging.info(web3.eth.get_transaction_count(wallet1_address))

        transaction = pancake_router.functions.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            Web3.to_wei(amount, 'ether'),
            amount_out_min,   # amountOutMin
            path,
            wallet1_address,
            deadline
        ).build_transaction({
            'from': wallet1_address,
            'gas': 300000,
            'gasPrice': web3.to_wei(average_gas_price, 'gwei'),
            'nonce': web3.eth.get_transaction_count(wallet1_address),
            # 'deadline': deadline
        })
    
        # Sign the transaction
        signed_transaction = web3.eth.account.sign_transaction(transaction, private_key=wallet1_private_key)

        # Send the raw transaction
        transaction_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        messageInProgress = context.bot.send_message(chat_id=update.effective_chat.id, text='Sending transaction... <o.o>')

        # logging.info("Everything okay until here ! Line 744 good. Let's start debugging !")
        # Wait for the transaction receipt
        transaction_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
                  
        context.bot.delete_message(chat_id=update.effective_chat.id, message_id=messageInProgress.message_id)
        if transaction_receipt.status == 1:
            basicEvent = token_contract.events.Transfer()

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                events = token_contract.events.Transfer().process_receipt(transaction_receipt)
            amount_sent = 0
            amount_received = 0

            if events: # If there are multiple 'Transfer' events, you can iterate over them to calculate the total amount sent and received
                for event in events:
                    if event['args']['to'] == wallet1_address:
                        amount_received += event['args']['value']
                    # Log the amount sent and received
            if decimals == 0:
                decimals = 18
            
            amount_received_formatted = (amount_received / 10 ** decimals)
            cake_amount = amount_received_formatted

            tx_hash = transaction_hash.hex()
            tx_hash_short = tx_hash[:4] + "..." + tx_hash[-4:]
            bscscan_url = f"https://bscscan.com/tx/{tx_hash}" 
            sent_url = f"https://bscscan.com/token/{usdt_token_address}"
            received_url = f"https://bscscan.com/token/{cake_contract_address}" 
            
            if cake_amount < 0.0001:
                cake_amount_formated = f"<0.0001"
            else:
                cake_amount_formated = f"{round(cake_amount, 4):.4f}".rstrip("0").rstrip(".")


            if amount < 0.0001:
                amount_formated = f'<0.0001'
            else:
                amount_formated = f"{round(amount, 4):.4f}".rstrip("0").rstrip(".")
            
            message = f"Successfully bought {cake_amount_formated} [{token_symbol}]({received_url}) for {amount_formated} [USDT]({sent_url}).\n"
            message += f"Tx hash: [{tx_hash_short}]({bscscan_url})\n"
            
            context.bot.send_message(chat_id=update.effective_chat.id, text=message, parse_mode='Markdown', disable_web_page_preview=True)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="Swap transaction failed.")
    except Exception as e:
        traceback.print_exc()
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"An error occurred: {str(e)}")







def buy_standard(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() not in admin_list:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')
        return


    # Extract the arguments from the user input
    args = update.message.text.split()[1:]
    if len(args) != 2:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /buy amount tokenAddress')
        return
    
    # Parse the amount and wallet tag
    try:
        amount = float(args[0])
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid amount. Please provide a valid number.')
        return
    
    cake_contract_address = args[1]

    wallet1_private_key = None

    if not private_keys:
        context.bot.send_message(chat_id=update.effective_chat.id, text='No private keys found. Please add a wallet first.')
        return

    wallet1_private_key = private_keys[0][0]
    
    try:
        receiver_address = Web3.to_checksum_address(cake_contract_address)
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Token address checksum failed. Have you put in the correct address?')
        return
    # Check if the provided token address is in the tokens list
    token = next((t for t in tokens if t[0] == receiver_address), None)
    if token is None:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid token address. Please provide a token address that is added using the /add_token command.')
        return

    wallet1_account = web3.eth.account.from_key(wallet1_private_key)
    wallet1_address = wallet1_account.address

    
    
    # URL of the ABI JSON file on GitHub
    abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeRouter.sol/PancakeRouter.json" 
    # Fetch the contents of the ABI JSON file
    response = requests.get(abi_url)
    abi_data = response.json()
    # Extract the ABI from the JSON data
    pancake_router_abi = abi_data

    token_abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeERC20.sol/PancakeERC20.json"

    response_token = requests.get(token_abi_url)
    token_abi_data = response_token.json()
    token_abi = token_abi_data

    # Perform the swap on PancakeSwap v2
    try:
        router_address = '0x10ED43C718714eb63d5aA57B78B54704E256024E'  # Address of the PancakeSwap router
        bnb_token = Web3.to_checksum_address('0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c')  # Address of BNB token
        cake_contract_address = Web3.to_checksum_address(cake_contract_address)  # Address of token

        pancake_router = web3.eth.contract(address=router_address, abi=pancake_router_abi)
        token_contract = web3.eth.contract(address=cake_contract_address, abi= token_abi)
        token_symbol = token_contract.functions.symbol().call()
        wallet1_account = web3.eth.account.from_key(wallet1_private_key)
        wallet1_address = wallet1_account.address
        
        deadline = int(time.time()) + 60  # Set deadline 1 minutes from now

        path = [bnb_token, cake_contract_address]
        # Get the amount of CAKE that will be received
        amounts = pancake_router.functions.getAmountsOut(Web3.to_wei(amount, 'ether'), path).call()
        
        try: 
            decimals = token_contract.functions.decimals().call()
            # logging.info("Decimals for this token: " + str(decimals))
        except Exception as e:
            logging.info("Could not fetch contract decimals. Defaulting to 18. Contact Dev for help.")
        
        cake_amount = Web3.from_wei(amounts[1], 'ether')
        # cake_amount = Web3.from_wei(amounts[-1], 'ether')
        amount_percentage = float(slippage / 100)
        amount_neg = amounts[1] * amount_percentage
        amount_out_min = amounts[1] - amount_neg
        amount_out_min = int(amount_out_min)
        # amount_out_min = float(amount_out_min)
        average_gas_price = get_average_gas_price()

        transaction = pancake_router.functions.swapExactETHForTokensSupportingFeeOnTransferTokens(
            amount_out_min,   # amountOutMin
            path,
            wallet1_address,
            deadline
        ).build_transaction({
            'from': wallet1_address,
            'value': Web3.to_wei(amount, 'ether'),
            'gas': 300000,
            'gasPrice': web3.to_wei(average_gas_price, 'gwei'),
            'nonce': web3.eth.get_transaction_count(wallet1_address),
            # 'deadline': deadline
        })
    
        # Sign the transaction
        signed_transaction = web3.eth.account.sign_transaction(transaction, private_key=wallet1_private_key)

        # Send the raw transaction
        transaction_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        messageInProgress = context.bot.send_message(chat_id=update.effective_chat.id, text='Sending transaction... <o.o>')

        # Wait for the transaction receipt
        transaction_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
                  
        context.bot.delete_message(chat_id=update.effective_chat.id, message_id=messageInProgress.message_id)
        if transaction_receipt.status == 1:
            basicEvent = token_contract.events.Transfer()

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                events = token_contract.events.Transfer().process_receipt(transaction_receipt)
            amount_sent = 0
            amount_received = 0

            if events: # If there are multiple 'Transfer' events, you can iterate over them to calculate the total amount sent and received
                for event in events:
                    if event['args']['to'] == wallet1_address:
                        amount_received += event['args']['value']
                    # Log the amount sent and received
            if decimals == 0:
                decimals = 18
            
            amount_received_formatted = (amount_received / 10 ** decimals)
            cake_amount = amount_received_formatted

            tx_hash = transaction_hash.hex()
            tx_hash_short = tx_hash[:4] + "..." + tx_hash[-4:]
            bscscan_url = f"https://bscscan.com/tx/{tx_hash}" 
            sent_url = f"https://bscscan.com/token/{bnb_token}"
            received_url = f"https://bscscan.com/token/{cake_contract_address}" 
            
            if cake_amount < 0.0001:
                cake_amount_formated = f"<0.0001"
            else:
                cake_amount_formated = f"{round(cake_amount, 4):.4f}".rstrip("0").rstrip(".")


            if amount < 0.0001:
                amount_formated = f'<0.0001'
            else:
                amount_formated = f"{round(amount, 4):.4f}".rstrip("0").rstrip(".")
            
            message = f"Successfully bought {cake_amount_formated} [{token_symbol}]({received_url}) for {amount_formated} [BNB]({sent_url}).\n"
            message += f"Tx hash: [{tx_hash_short}]({bscscan_url})\n"
            
            context.bot.send_message(chat_id=update.effective_chat.id, text=message, parse_mode='Markdown', disable_web_page_preview=True)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="Swap transaction failed.")
    except Exception as e:
        traceback.print_exc()
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"An error occurred: {str(e)}")

def sell(update: Update, context: CallbackContext) -> None:
    # Extract the arguments from the user input
    args = update.message.text.split()[1:]
    if len(args) != 2:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /sell amount tokenAddress')
        return
    
    # Parse the amount and wallet tag
    try:
        amount = float(args[0])
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid amount. Please provide a valid number.')
        return
   
    cake_contract_address = args[1]

    wallet1_private_key = None

    if not private_keys:
        context.bot.send_message(chat_id=update.effective_chat.id, text='No private keys found. Please add a wallet first.')
        return

    wallet1_private_key = private_keys[0][0]
    
    try:
        receiver_address = Web3.to_checksum_address(cake_contract_address)  # Need to rename this variable
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Token address checksum failed. Have you put in the correct address?')
        return

    # Check if the provided token address is in the tokens list
    token = next((t for t in tokens if t[0] == receiver_address), None) #Need to rename this variable
    if token is None:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid token address. Please provide a token address that is added using the /add_token command.')
        return

    wallet1_account = web3.eth.account.from_key(wallet1_private_key)
    wallet1_address = wallet1_account.address

    # URL of the ABI JSON file on GitHub
    abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeRouter.sol/PancakeRouter.json" 
    # Fetch the contents of the ABI JSON file
    response = requests.get(abi_url)
    abi_data = response.json()
    # Extract the ABI from the JSON data
    pancake_router_abi = abi_data
        
    token_abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeERC20.sol/PancakeERC20.json"

    response_token = requests.get(token_abi_url)
    token_abi_data = response_token.json()
    token_abi = token_abi_data

    try: 
        usdt_token_address = Web3.to_checksum_address('0x55d398326f99059fF775485246999027B3197955')
        usdt_contract = web3.eth.contract(address=usdt_token_address, abi=token_abi)
    except Exception as e:
        traceback.print_exc()
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"An error occurred: {str(e)}")

   
    # Perform the swap on PancakeSwap v2
    try:
        raw_router_address = '0x10ED43C718714eb63d5aA57B78B54704E256024E'  # Address of the PancakeSwap router
        router_address = Web3.to_checksum_address(raw_router_address)
        bnb_contract_address = Web3.to_checksum_address('0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c')
        cake_token = Web3.to_checksum_address(cake_contract_address)  # Address of CAKE token

        pancake_router = web3.eth.contract(address=router_address, abi=pancake_router_abi)
        wallet1_account = web3.eth.account.from_key(wallet1_private_key)
        wallet1_address = wallet1_account.address
        
        deadline = int(time.time()) + 60  # Set deadline 1 minute from now

        # Get the amount of BNB that will be received
        path = []
        amounts = []

       
        # APPROVALS AND ALLOWANCE CHECK
        average_gas_price = get_average_gas_price()


        cake_contract_address = Web3.to_checksum_address(cake_contract_address)  # Address of token

        token_contract = web3.eth.contract(address=cake_contract_address, abi=token_abi)

        try: 
            decimals = token_contract.functions.decimals().call()
            logging.info("Decimals for this token: " + str(decimals))
        except Exception as e:
            logging.info("Could not fetch contract decimals. Defaulting to 18. Contact Dev for help.")
            decimals = 18

        amount_cleaned = int(amount * 10**decimals)
        try:
            path = [cake_contract_address, bnb_contract_address, usdt_token_address]
            amounts = pancake_router.functions.getAmountsOut(amount_cleaned, path).call()
        except Exception as e:
            try:
                logging.info('TOKEN/BNB PATH not found. Looking for TOKEN/USDT PATH...')
                path = [cake_contract_address, usdt_token_address]
                amounts = pancake_router.functions.getAmountsOut(amount_cleaned, path).call()
            except Exception as e:
                logging.info("No path was found. Contact Dev for help.")
                traceback.print_exc()
                context.bot.send_message(chat_id=update.effective_chat.id, text=f"An error occurred: {str(e)}")

                return

        usdt_amount = Web3.from_wei(amounts[-1], 'ether')
        cake_amount = amount_cleaned / 10**decimals
 
    
        #APPROVAL CHECK
        current_allowance = token_contract.functions.allowance(wallet1_address, router_address).call()
        token_symbol = token_contract.functions.symbol().call()
        
        if current_allowance < amounts[0]:
            max_approval_amount = 2**256 - 1  # Approve the maximum possible amount

            # Approve the spending of tokens by the router contract
            approve_tx = token_contract.functions.approve(router_address, max_approval_amount).build_transaction({
                'from': wallet1_address,
                'gas': 200000,
                'gasPrice': web3.to_wei(average_gas_price, 'gwei'),
                'nonce': web3.eth.get_transaction_count(wallet1_address)
            })

            signed_approve_txn = web3.eth.account.sign_transaction(approve_tx, private_key=wallet1_private_key)
            approve_tx_hash = web3.eth.send_raw_transaction(signed_approve_txn.rawTransaction)
            approve_tx_receipt = web3.eth.wait_for_transaction_receipt(approve_tx_hash)

            if approve_tx_receipt['status'] == 1:
                logging.info("Token approval successful")
            else:
                logging.error("Token approval failed")# Approve the spending of tokens by the router contract
        # ... (approval step)
        else:
            logging.info("Sufficient allowance already granted")


        amount_percentage = float(slippage / 100)
        amount_neg = amounts[-1] * amount_percentage #array[-1] to access the last element
        amount_out_min = amounts[-1] - amount_neg
        amount_out_min = int(amount_out_min)
        # amount_out_min = float(amount_out_min)
 

        transaction = pancake_router.functions.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amounts[0],  # amountIn
            amount_out_min,  # amountOutMin
            path,
            wallet1_address,
            deadline
        ).build_transaction({
            'from': wallet1_address,
            'gas': 300000,
            'gasPrice': web3.to_wei(average_gas_price, 'gwei'),
            'nonce': web3.eth.get_transaction_count(wallet1_address)
        })

        # Sign the transaction
        signed_transaction = web3.eth.account.sign_transaction(transaction, private_key=wallet1_private_key)

        # Send the raw transaction
        transaction_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        messageInProgress = context.bot.send_message(chat_id=update.effective_chat.id, text='Sending transaction... <o.o>')
        # Wait for the transaction receipt
        transaction_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
                  
        context.bot.delete_message(chat_id=update.effective_chat.id, message_id=messageInProgress.message_id)
        if transaction_receipt.status == 1:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                events = token_contract.events.Transfer().process_receipt(transaction_receipt)
            
            amount_sent = 0
            amount_received = 0

            if events: # If there are multiple 'Transfer' events, you can iterate over them to calculate the total amount sent and received
                for event in events:
                    if event['args']['to'] == wallet1_address:
                        amount_received += event['args']['value']
                    # Log the amount sent and received
            amount_received_formatted = web3.from_wei(amount_received, 'ether')
            usdt_amount = amount_received_formatted

            tx_hash = transaction_hash.hex()
            tx_hash_short = tx_hash[:4] + "..." + tx_hash[-4:]
            bscscan_url = f"https://bscscan.com/tx/{tx_hash}" 
            sent_url = f"https://bscscan.com/token/{usdt_token_address}"
            received_url = f"https://bscscan.com/token/{cake_contract_address}" 
            
            if cake_amount < 0.0001:
                cake_amount_formated = f"<0.0001"
            else:
                cake_amount_formated = f"{round(cake_amount, 4):.4f}".rstrip("0").rstrip(".")

            if usdt_amount < 0.0001:
                amount_formated = f'<0.0001'
            else:
                amount_formated = f"{round(usdt_amount, 4):.4f}".rstrip("0").rstrip(".")


            message = f"Successfully sold {cake_amount_formated} [{token_symbol}]({received_url}) for {amount_formated} [USDT]({sent_url}).\n"
            message += f"Tx hash: [{tx_hash_short}]({bscscan_url})\n"
            
            context.bot.send_message(chat_id=update.effective_chat.id, text=message, parse_mode='Markdown', disable_web_page_preview=True)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="Swap transaction failed.")
    except Exception as e:
        traceback.print_exc()
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"An error occurred: {str(e)}")






def sell_standard(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() not in admin_list:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')
        return

   # Extract the arguments from the user input
    args = update.message.text.split()[1:]
    if len(args) != 2:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid command format. Usage: /sell amount tokenAddress')
        return
    
    # Parse the amount and wallet tag
    try:
        amount = float(args[0])
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid amount. Please provide a valid number.')
        return
   
    cake_contract_address = args[1]

    wallet1_private_key = None

    if not private_keys:
        context.bot.send_message(chat_id=update.effective_chat.id, text='No private keys found. Please add a wallet first.')
        return

    wallet1_private_key = private_keys[0][0]
    
    try:
        receiver_address = Web3.to_checksum_address(cake_contract_address)  # Need to rename this variable
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Token address checksum failed. Have you put in the correct address?')
        return

    # Check if the provided token address is in the tokens list
    token = next((t for t in tokens if t[0] == receiver_address), None) #Need to rename this variable
    if token is None:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid token address. Please provide a token address that is added using the /add_token command.')
        return

    wallet1_account = web3.eth.account.from_key(wallet1_private_key)
    wallet1_address = wallet1_account.address

    # URL of the ABI JSON file on GitHub
    abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeRouter.sol/PancakeRouter.json" 
    # Fetch the contents of the ABI JSON file
    response = requests.get(abi_url)
    abi_data = response.json()
    # Extract the ABI from the JSON data
    pancake_router_abi = abi_data

    # Perform the swap on PancakeSwap v2
    try:
        raw_router_address = '0x10ED43C718714eb63d5aA57B78B54704E256024E'  # Address of the PancakeSwap router
        router_address = Web3.to_checksum_address(raw_router_address)
        bnb_contract_address = Web3.to_checksum_address('0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c')
        cake_token = Web3.to_checksum_address(cake_contract_address)  # Address of CAKE token

        pancake_router = web3.eth.contract(address=router_address, abi=pancake_router_abi)
        wallet1_account = web3.eth.account.from_key(wallet1_private_key)
        wallet1_address = wallet1_account.address
        
        deadline = int(time.time()) + 60  # Set deadline 1 minute from now

        path = [cake_token, bnb_contract_address]
        # Get the amount of BNB that will be received


       
        # APPROVALS AND ALLOWANCE CHECK
        average_gas_price = get_average_gas_price()
        
        token_abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeERC20.sol/PancakeERC20.json"

        response_token = requests.get(token_abi_url)
        token_abi_data = response_token.json()
        token_abi = token_abi_data

        cake_contract_address = Web3.to_checksum_address(cake_contract_address)  # Address of token

        token_contract = web3.eth.contract(address=cake_contract_address, abi=token_abi)

        try: 
            decimals = token_contract.functions.decimals().call()
            logging.info("Decimals for this token: " + str(decimals))
        except Exception as e:
            logging.info("Could not fetch contract decimals. Defaulting to 18. Contact Dev for help.")
            decimals = 18

        amount_cleaned = int(amount * 10**decimals)
        amounts = pancake_router.functions.getAmountsOut(amount_cleaned, path).call()
        bnb_amount = Web3.from_wei(amounts[1], 'ether')
        cake_amount = amount_cleaned / 10**decimals
 
    
        #APPROVAL CHECK
        current_allowance = token_contract.functions.allowance(wallet1_address, router_address).call()
        token_symbol = token_contract.functions.symbol().call()
        
        if current_allowance < amounts[0]:
            max_approval_amount = 2**256 - 1  # Approve the maximum possible amount

            # Approve the spending of tokens by the router contract
            approve_tx = token_contract.functions.approve(router_address, max_approval_amount).build_transaction({
                'from': wallet1_address,
                'gas': 200000,
                'gasPrice': web3.to_wei(average_gas_price, 'gwei'),
                'nonce': web3.eth.get_transaction_count(wallet1_address)
            })

            signed_approve_txn = web3.eth.account.sign_transaction(approve_tx, private_key=wallet1_private_key)
            approve_tx_hash = web3.eth.send_raw_transaction(signed_approve_txn.rawTransaction)
            approve_tx_receipt = web3.eth.wait_for_transaction_receipt(approve_tx_hash)

            if approve_tx_receipt['status'] == 1:
                logging.info("Token approval successful")
            else:
                logging.error("Token approval failed")# Approve the spending of tokens by the router contract
        # ... (approval step)
        else:
            logging.info("Sufficient allowance already granted")


        amount_percentage = float(slippage / 100)
        amount_neg = amounts[1] * amount_percentage
        amount_out_min = amounts[1] - amount_neg
        amount_out_min = int(amount_out_min)
        # amount_out_min = float(amount_out_min)
 

        transaction = pancake_router.functions.swapExactTokensForETHSupportingFeeOnTransferTokens(
            amounts[0],  # amountIn
            amount_out_min,  # amountOutMin
            path,
            wallet1_address,
            deadline
        ).build_transaction({
            'from': wallet1_address,
            'gas': 300000,
            'gasPrice': web3.to_wei(average_gas_price, 'gwei'),
            'nonce': web3.eth.get_transaction_count(wallet1_address)
        })

        # Sign the transaction
        signed_transaction = web3.eth.account.sign_transaction(transaction, private_key=wallet1_private_key)

        # Send the raw transaction
        transaction_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        messageInProgress = context.bot.send_message(chat_id=update.effective_chat.id, text='Sending transaction... <o.o>')
        # Wait for the transaction receipt
        transaction_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
                  
        context.bot.delete_message(chat_id=update.effective_chat.id, message_id=messageInProgress.message_id)
        if transaction_receipt.status == 1:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                events = token_contract.events.Transfer().process_receipt(transaction_receipt)
            
            amount_sent = 0
            amount_received = 0

            if events: # If there are multiple 'Transfer' events, you can iterate over them to calculate the total amount sent and received
                for event in events:
                    if event['args']['to'] == router_address:
                        amount_received += event['args']['value']
                    # Log the amount sent and received
            amount_received_formatted = web3.from_wei(amount_received, 'ether')
            bnb_amount = amount_received_formatted

            tx_hash = transaction_hash.hex()
            tx_hash_short = tx_hash[:4] + "..." + tx_hash[-4:]
            bscscan_url = f"https://bscscan.com/tx/{tx_hash}" 
            sent_url = f"https://bscscan.com/token/{bnb_contract_address}"
            received_url = f"https://bscscan.com/token/{cake_contract_address}" 
            
            if cake_amount < 0.0001:
                cake_amount_formated = f"<0.0001"
            else:
                cake_amount_formated = f"{round(cake_amount, 4):.4f}".rstrip("0").rstrip(".")

            logging.info("BNB Amount received: " + str(bnb_amount))

            if bnb_amount < 0.0001:
                amount_formated = f'<0.0001'
            else:
                amount_formated = f"{round(bnb_amount, 4):.4f}".rstrip("0").rstrip(".")


            message = f"Successfully sold {cake_amount_formated} [{token_symbol}]({received_url}) for {amount_formated} [BNB]({sent_url}).\n"
            message += f"Tx hash: [{tx_hash_short}]({bscscan_url})\n"
            
            context.bot.send_message(chat_id=update.effective_chat.id, text=message, parse_mode='Markdown', disable_web_page_preview=True)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="Swap transaction failed.")
    except Exception as e:
        traceback.print_exc()
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"An error occurred: {str(e)}")


def add_token(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() not in admin_list:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')
        return

    args = context.args
    if len(args) != 1:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Please provide the smart contract address.")
        return
    
    address = args[0]
    
    # Check if the address is a valid checksum
    try:
        checksum_address = Web3.to_checksum_address(address)
    except ValueError:
        context.bot.send_message(chat_id=update.effective_chat.id, text='Invalid address checksum. Please provide a valid address.')
        return
    
    # Check if there is code at the given address
    code = web3.eth.get_code(checksum_address)
    if code == b'':
        context.bot.send_message(chat_id=update.effective_chat.id, text='No code found at the provided address. Please enter a valid smart contract address.')
        return
    # Check if the token is already added
    for token in tokens:
        if token[0] == checksum_address:
            context.bot.send_message(chat_id=update.effective_chat.id, text='Token already added.')
            return


    token_abi_url = "https://raw.githubusercontent.com/pancakeswap/pancake-smart-contracts/master/projects/exchange-protocol/data/abi/contracts/PancakeERC20.sol/PancakeERC20.json"

    response_token = requests.get(token_abi_url)
    token_abi_data = response_token.json()
    token_abi = token_abi_data

    # Fetch the symbol using web3 call
    contract = web3.eth.contract(address=checksum_address, abi=token_abi)
    try:
        symbol = contract.functions.symbol().call()
    except Exception as e:
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"Failed to fetch the token symbol: {str(e)}")
        return
    
    # Add the token address and symbol to the list
    tokens.append((checksum_address, symbol))
    context.bot.send_message(chat_id=update.effective_chat.id, text=f'Token {symbol} added successfully with address {checksum_address}.')


def list_tokens(update: Update, context:CallbackContext) -> None:
    if not tokens:
        context.bot.send_message(chat_id=update.effective_chat.id, text='No tokens added yet.')
        return
    
    message = "List of added tokens:\n\n"
    for i, token in enumerate(tokens):
        address, symbol = token
        message += f"{i+1}. Symbol: {symbol}\n   Address: {address}\n\n"
    
    context.bot.send_message(chat_id=update.effective_chat.id, text=message)


def remove_token(update:Update, context:CallbackContext) -> None:
    user = update.message.from_user.username
    if user.lower() not in admin_list:
        context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this command.')
        return

    args = context.args
    if len(args) != 1:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Please provide the token symbol or address to remove.")
        return
    
    token_identifier = args[0]
    
    # Check if the token is in the list
    removed = False
    for token in tokens:
        address, symbol = token
        if token_identifier == address or token_identifier == symbol:
            tokens.remove(token)
            removed = True
            break
    
    if removed:
        context.bot.send_message(chat_id=update.effective_chat.id, text=f'Token {token_identifier} removed successfully.')
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text=f'Token {token_identifier} not found.')

# Register command handlers
dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(CommandHandler("addadmin", add_admin, filters=Filters.chat_type.private))
dispatcher.add_handler(CommandHandler("removeadmin", remove_admin, filters=Filters.chat_type.private))
dispatcher.add_handler(CommandHandler("listadmins", list_admins, filters=Filters.chat_type.private))
dispatcher.add_handler(CommandHandler("help", help_command))
dispatcher.add_handler(CommandHandler("add_privatekey", add_privatekey, filters=Filters.chat_type.private))
dispatcher.add_handler(CommandHandler("remove_privatekey", remove_privatekey, filters=Filters.chat_type.private))
dispatcher.add_handler(CommandHandler("list_privatekeys", list_privatekeys, filters=Filters.chat_type.private))
dispatcher.add_handler(CommandHandler("edit_privatekey", edit_privatekey, filters=Filters.chat_type.private))
dispatcher.add_handler(CommandHandler("list_wallets", list_wallets, filters=Filters.chat_type.private))
dispatcher.add_handler(CommandHandler("gas_prices", gas_prices))
dispatcher.add_handler(CommandHandler("bnb_price", bnb_price))  
dispatcher.add_handler(CommandHandler("setup", setup, filters=Filters.chat_type.private)) 
dispatcher.add_handler(CommandHandler("listwallet_balances", listwallet_balances, filters=Filters.chat_type.private))
dispatcher.add_handler(CommandHandler("send_bnb", send_bnb))  
dispatcher.add_handler(CommandHandler("buy", buy)) 
dispatcher.add_handler(CommandHandler("sell", sell)) 
dispatcher.add_handler(CommandHandler("buy_standard", buy_standard, filters=Filters.chat_type.private)) 
dispatcher.add_handler(CommandHandler("sell_standard", sell_standard, filters=Filters.chat_type.private))  
dispatcher.add_handler(CommandHandler("version", version))  
dispatcher.add_handler(CommandHandler("transfer", transfer))  
dispatcher.add_handler(CommandHandler("set_slippage", set_slippage, filters=Filters.chat_type.private))  
dispatcher.add_handler(CommandHandler("get_slippage", get_slippage, filters=Filters.chat_type.private))  

dispatcher.add_handler(CommandHandler("add_token", add_token))  
dispatcher.add_handler(CommandHandler("list_tokens", list_tokens))  
dispatcher.add_handler(CommandHandler("remove_token", remove_token))  

# Register error handler
dispatcher.add_error_handler(error_handler)

# Start the bot
updater.start_polling()
updater.idle()



