import grpc
import zkp_auth_pb2
import zkp_auth_pb2_grpc
import os
import random
from utils import *

LOGIN_DIR = "."
LOGIN_FNAME = "login_params.txt"

def init():
    channel = grpc.insecure_channel('localhost:50051')
    stub = zkp_auth_pb2_grpc.AuthStub(channel)
    return channel, stub

def register(channel, stub, username):    
    # Register Request
    x,reg_y1,reg_y2 = client_gen_register_values()
    # print("**Register**\nx:\n",x,"\ny1:\n", reg_y1, "\ny2:\n", reg_y2)

    register_request = zkp_auth_pb2.RegisterRequest(user=username, y1=str(reg_y1), y2=str(reg_y2))
    register_response = stub.Register(register_request)
    print("Register response status:", register_response.status)
    if 200 == register_response.status:
        client_store_login_params(os.path.join(LOGIN_DIR,LOGIN_FNAME), username, x, reg_y1, reg_y2)

def login(channel, stub, username):
    reg_params_exist, reg_username, reg_x, reg_y1, reg_y2 = client_load_reg_params(os.path.join(LOGIN_DIR,LOGIN_FNAME))
    if not reg_params_exist or reg_username != username:
        print("ERROR: user register parameters do not exist for user: " + username)
        return

    # print("**Login**\nx:\n",reg_x,"\ny1:\n", reg_y1, "\ny2:\n", reg_y2)
    eph_k, eph_r1, eph_r2 = client_gen_ephemeral()
    # print("k:\n",eph_k,"\nr1:\n", eph_r1, "\nr2:\n", eph_r2)

    channel = grpc.insecure_channel('localhost:50051')
    stub = zkp_auth_pb2_grpc.AuthStub(channel)
    print("Building AuthenticationChallengeRequest")
    # Authentication Challenge Request
    challenge_request = zkp_auth_pb2.AuthenticationChallengeRequest(user=username, r1=str(eph_r1), r2=str(eph_r2))
    challenge_response = stub.CreateAuthenticationChallenge(challenge_request)
    print("Received challenge_response")
    print("Authentication Challenge response auth_id:", challenge_response.auth_id, "c:", challenge_response.c)

    x = gmpy2.mpz(reg_x)
    c = gmpy2.mpz(challenge_response.auth_id)
    if 0 == c:
        print("ERROR: challenge not received")
        return
    # print("x:", x, "\nk:",eph_k, "\nc:",c)

    proof = client_prove(x,eph_k, c)
    print("proof: ", proof)

    # Verify Authentication Request
    verify_request = zkp_auth_pb2.AuthenticationAnswerRequest(auth_id=challenge_response.auth_id, s=str(proof))
    verify_response = stub.VerifyAuthentication(verify_request)
    print("Verify Authentication response session_id:", verify_response.session_id)

if __name__ == '__main__':
    channel, stub = init()
    # register(channel, stub, "avishay")
    login(channel, stub, "avishay")
