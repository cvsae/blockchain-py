import pickle
from utils import GetAppDir


class Wallets(object):
    """ Wallet stores private and public keys.

    Args:

    Attributes:
        wallets (dict): a wallets dict.
    """

    wallet_file = GetAppDir() + str(r'\wallet.dat')

    def __init__(self):

        try:
            with open(self.wallet_file, 'rb') as f:
                self.wallets = pickle.load(f)
        except FileNotFoundError:
            self.wallets = {}

    def add_wallet(self, addr, wallet):
        self.wallets[addr] = wallet

    def get_addresses(self):
        return [addr for addr in self.wallets.keys()]

    def get_wallet(self, addr):
        return self.wallets[addr]

    def save_to_file(self):
        try:
            with open(self.wallet_file, 'wb') as f:
                pickle.dump(self.wallets, f)
        except Exception as e:
            return False
        else:
            return True
