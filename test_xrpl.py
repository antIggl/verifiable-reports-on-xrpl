#!/bin/env python3

# testing implementation that signs and verifies reports on XRPL

import argparse
import os
import sys
import time
import json
import collections
import hashlib
import binascii

import base64
# url for testnet network.
surl='https://s.altnet.rippletest.net:51234/'

from xrpl.clients import JsonRpcClient
from xrpl.wallet import generate_faucet_wallet, Wallet
from xrpl.core import keypairs
from xrpl.account import does_account_exist, get_account_info, get_balance, get_next_valid_seq_number
from xrpl.transaction import *
from xrpl.models import transactions
import xrpl


def sign_data( signer, data) -> bytes:
    """
    Signs the data using the keys of signer account wallet.
    """
    encoded_data=json.dumps(data,sort_keys=True).encode('utf-8')
    #print('Encoded_data',encoded_data)
    hashed_data = hashlib.sha512(encoded_data).digest()
    #print('hashed:', hashed_data)
    msignature = xrpl.core.keypairs.sign(hashed_data,signer.private_key)
    return msignature
    

def _verify_signed_data(data,  signature,pubkey) -> bool:
    encoded_data=json.dumps(data,sort_keys=True).encode('utf-8')
    #print('to_get_verified_data',encoded_data)
    hashed_data = hashlib.sha512(encoded_data).digest()
    #print('verif. hashed:', hashed_data)
    return xrpl.core.keypairs.is_valid_message(hashed_data,signature,pubkey)


def verify_data(client,data,tx_id) -> bool:
    """
    Does the verification of the data with blockchain
    """
    # retrieve tx
    txdata=xrpl.transaction.get_transaction_from_hash(tx_id,client,binary=False)
    #print(txdata)
    # txpayment=transactions.Payment.from_xrpl(txdata.result)
    # txpayment.memos[0]
    #txdata.result['Memos'][0]
    txmemo=transactions.Memo.from_xrpl(txdata.result['Memos'][0])
    memo_format = binascii.unhexlify(txmemo.memo_format).decode('utf-8')
    memo_data=None
    if memo_format=='application/json' :
        memo_data = json.loads(binascii.unhexlify(txmemo.memo_data))
    else:
        #raise 
        return False
        
    # verify data with signatures and timestamps
    # check verification with signature
    a = _verify_signed_data(data,binascii.unhexlify(memo_data['issuer_signature']),memo_data['issuer_pubkey'])
    a &= _verify_signed_data(data,binascii.unhexlify(memo_data['cosigner_signature']),memo_data['cosigner_pubkey'])
    a &= (data['timestamp']==memo_data['timestamp'])
    #a &= (txdata.result['Account'] == memo_data['issu
    #if a:
        # find domain names
        
    return a
    
def submit_transaction( client,sender, memo_data, receiver_addr):
    """
    Helper function implementing the transaction submission for report issuance
    """
    mytx_memo = transactions.Memo.from_dict({
        "memo_data": json.dumps(memo_data,sort_keys=True).encode('utf8').hex(),
        "memo_format": "application/json".encode('utf-8').hex()
        })
    
    mytx_payment = transactions.Payment(account=sender.classic_address,
                                       amount="100",
                                       destination = receiver_addr,
                                       memos=[mytx_memo],
                                       last_ledger_sequence=xrpl.ledger.get_latest_validated_ledger_sequence(client)+10,
                                       sequence=xrpl.account.get_next_valid_seq_number(sender.classic_address,client),
                                       fee=xrpl.ledger.get_fee(client))
    #sequence=funding_account.sequence,
    print(mytx_payment)
    mytx_signed = safe_sign_transaction(mytx_payment, sender)
    
    mytx_response = send_reliable_submission(mytx_signed,client)
    print(mytx_response)
    if mytx_response.is_successful():
        return mytx_response
    else:
        return None

def issue_report(client, issuer, cosigner, report_data, verifier):
    """
    Issues a report on blockchain
    client: the JsonRpcClient
    issuer: the account wallet (xrpl.wallet.Wallet) issues the report
    cosigner: the account wallet (xrpl.wallet.Wallet) cosigns the report
    report_data: dict with the data to be signed. can be anything.
    verifier: the account wallet (actually only classic_address is used) of the destination of the transaction
    
    returns None on Failure.
            a tuple (<base64 encoded signed data>,<transaction ID/hash>)
    """
    #signing data
    txmemo_data={}
    txmemo_data ['timestamp']=report_data['timestamp']
    txmemo_data ['issuer_signature']= sign_data(issuer,report_data)
    txmemo_data ['issuer_pubkey'] = issuer.public_key
    txmemo_data ['cosigner_signature']= sign_data(cosigner,sample_data)
    txmemo_data ['cosigner_pubkey'] = cosigner.public_key
     # check verification with signature
    a = _verify_signed_data(report_data,binascii.unhexlify(txmemo_data['issuer_signature']),txmemo_data['issuer_pubkey'])
    a &= _verify_signed_data(report_data,binascii.unhexlify(txmemo_data['cosigner_signature']),txmemo_data['cosigner_pubkey'])
    if not a:
        print ('Error: signature verification failed')
        return None
    print ('verification {}'.format(('PASSED' if a else 'FAILED')))
    
    encoded_report_data=base64.b64encode(json.dumps(report_data,sort_keys=True).encode('utf-8'))
    
    mytx= submit_transaction(client,issuer,txmemo_data, verifier.classic_address)
    if mytx:
        return (encoded_report_data, mytx.result['hash'])
    else:
        return None #(report_data, None)

def check_issued_report(client,func_out):
    """
    Used to test if the issued report can be verified in blockchain. 
    func_out: the return tuple of issue_report ()
    """
    alldata=json.loads(base64.b64decode(func_out[0]))
    print(alldata)
    txhash=func_out[1]
    print (txhash)
    
    print('Verified: {}'.format(verify_data(client, alldata, txhash)))
    #return ()

    
def fund_account(client,funding_account,dest_account_addr,amount):
    mytx_payment = transactions.Payment(account=funding_account.classic_address,
                                       amount=amount,
                                       destination = dest_account_addr,
                                       last_ledger_sequence=xrpl.ledger.get_latest_validated_ledger_sequence(client)+10,
                                       sequence=xrpl.account.get_next_valid_seq_number(funding_account.classic_address,client),
                                       fee=xrpl.ledger.get_fee(client))
    #sequence=funding_account.sequence,
    print(mytx_payment)
    mytx_signed = safe_sign_transaction(mytx_payment, funding_account)
    
    mytx_response = send_reliable_submission(mytx_signed,client)
    print(mytx_response)
    
    print ('Funding account {} was {}'.format(dest_account_addr,('SUCCESSFUL' if mytx_response.is_successful() else 'FAILED')))

def set_domain_to_account(client, account,domain):
    
    #The Domain field is represented as the hex string of the lowercase ASCII of the domain
    encoded_domain= domain.lower().encode('ascii').hex()
    tx_accountset = transactions.AccountSet(account=account.classic_address, 
                                            domain=encoded_domain,
                                            last_ledger_sequence=xrpl.ledger.get_latest_validated_ledger_sequence(client)+10,
                                            sequence=xrpl.account.get_next_valid_seq_number(account.classic_address,client),
                                            fee=xrpl.ledger.get_fee(client))
    
    print (tx_accountset)
    
    mytx_signed = safe_sign_transaction(tx_accountset, account)
    
    mytx_response = send_reliable_submission(mytx_signed,client)
    print(mytx_response)
    print ('Transaction AccountSet for account {} was {}'.format(account.classic_address,('SUCCESSFUL' if mytx_response.is_successful() else 'FAILED')))
    
def retrieve_account_info(client,account_addr):
    acc_info_resp = xrpl.account.get_account_info(account_addr,client)
    acc_balance=acc_info_resp.result['account_data']['Balance']
    acc_domain=binascii.unhexlify(acc_info_resp.result['account_data']['Domain'])
    acc_previousTx = acc_info_resp.result['account_data']['PreviousTxnID']
    
    
    return { 'address':account_addr, 'balance':acc_balance, 'domain':acc_domain, 'PreviousTxnID':acc_previousTx}

    
def create_account(client, funding_account,domain=None,seed=None):
    
    if not seed:
        seed=keypairs.generate_seed()
    acc_existed=True
    while(acc_existed):
        pubkey,privkey = keypairs.derive_keypair(seed)
        acc_addr = keypairs.derive_classic_address(pubkey)
        acc_existed = does_account_exist(acc_addr,client)
        
        
    new_acc={ "classic_address":acc_addr,
             "public_key":pubkey,
             "private_key":privkey,
             "seed":seed}
        
    print (new_acc)
    # the account does not exist... let's create one.
    # to create an account, a new transaction with at least 20XRP should be submitted.
    mytx_payment = transactions.Payment(account=funding_account.classic_address,
                                       amount="20000000",
                                       destination = acc_addr,
                                       last_ledger_sequence=xrpl.ledger.get_latest_validated_ledger_sequence(client)+10,
                                       sequence=xrpl.account.get_next_valid_seq_number(funding_account.classic_address,client),
                                       fee=xrpl.ledger.get_fee(client))
    #sequence=funding_account.sequence,
    print(mytx_payment)
    mytx_signed = safe_sign_transaction(mytx_payment, funding_account)
    
    mytx_response = send_reliable_submission(mytx_signed,client)
    print(mytx_response)
    
    return collections.namedtuple("Wallet",new_acc.keys())(*new_acc.values())
    
    
def create_testnet_account(client):
    twallet = generate_faucet_wallet(client)
    return twallet

def save_wallet_to_file(wallet, filename):
    with open(filename,'w') as f:
        json.dump(wallet._asdict(),f,indent=4,sort_keys=True)
        
def restore_wallet_from_file(filename):
    with open(filename,'r') as f:
        mswallet=json.load(f)
    #print(mswallet)
    return collections.namedtuple("Wallet",mswallet.keys())(*mswallet.values())


if __name__=='__main__':
    

    sample_data={
    "first_name":"John",
    "second_name":"Sample",
    "date_of_birth": "28/02/1990",
    "passport_id": "JS123456",
    "timestamp":34564958,
    "test_id":"123123",
    "result":"Negative",
    "test_type":"SARS-COV19"
    }



    client = JsonRpcClient(surl)

    # creating a wallet
    #testnet_wallet = generate_faucet_wallet(client)
    #print ("Testnet wallet: \n {}".format(testnet_wallet))
    

    #or
    #generate seed
    #seed = keypairs.generate_seed()
    #pubkey, privkey = keypairs.derive_keypair(seed)
    #account_addr = keypairs.derive_classic_address(pubkey)
    #or
    #seed = keypairs.generate_seed()
    #wallet_from_seed = Wallet(seed,0)
    
    #print("Seed : \n {}".format(seed))
    #print("Wallet Address: \n {}".format(wallet_from_seed))
    
    funding_account = restore_wallet_from_file("./keys/testnet_wallet_keys.json")
    funding_account_balance = xrpl.account.get_balance(address=funding_account.classic_address, client=client)
    print("funding account: {} \n \t Remaining balance: {} drops".format(funding_account,funding_account_balance))
    #funding_account_wallet = collections.namedtuple("Wallet",funding_account.keys())(*funding_account.values())
    
    issuer_account = restore_wallet_from_file("./keys/testnet_account1_keys.json")
    issuer_account_balance = xrpl.account.get_balance(address=issuer_account.classic_address, client=client)
    print("issuer account: {} \n \t Remaining balance: {} drops".format(issuer_account,issuer_account_balance))
    
    verifier_account = restore_wallet_from_file("./keys/testnet_account2_keys.json")
    verifier_account_balance = xrpl.account.get_balance(address=verifier_account.classic_address, client=client)
    
    print("verifier account: {} \n \t Remaining balance: {} drops".format(verifier_account, verifier_account_balance))
    
    cosigner_account = restore_wallet_from_file("./keys/testnet_account3_keys.json")
    cosigner_account_balance = xrpl.account.get_balance(address=cosigner_account.classic_address, client=client)
    
    print("cosigner account: {} \n \t Remaining balance: {} drops".format(cosigner_account,cosigner_account_balance))
    
    #signing data
    #txmemo_data={}
    #txmemo_data ['timestamp']=sample_data['timestamp']
    #txmemo_data ['issuer_signature']= sign_data(issuer_account,sample_data)
    #txmemo_data ['issuer_pubkey'] = issuer_account.public_key
    #txmemo_data ['cosigner_signature']= sign_data(cosigner_account,sample_data)
    #txmemo_data ['cosigner_pubkey'] = cosigner_account.public_key
    
    #check verification with signature
    #a = _verify_signed_data(sample_data,binascii.unhexlify(txmemo_data['issuer_signature']),txmemo_data['issuer_pubkey'])
    #a &= _verify_signed_data(sample_data,binascii.unhexlify(txmemo_data['cosigner_signature']),txmemo_data['cosigner_pubkey'])
    
    #print ('verification {}'.format(('PASSED' if a else 'FAILED')))
    
    #mytx_resp.result['hash']

    
