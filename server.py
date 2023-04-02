import grpc
from concurrent import futures
import zkp_auth_pb2
import zkp_auth_pb2_grpc
import time
import os

from utils import *


USERS_DIR = "users"
SESSIONS_DIR = "sessions"
USER_LOGIN_FNAME = "generic_user"


G = ZZp_star()

def str2mpz(x):
    try:
        x = gmpy2.mpz(x)
        return x
    except(e):
        print("error converting to gmpy2.mpz", x)

def verify_register_request(y1,y2):
    y1 = str2mpz(y1)
    y2 = str2mpz(y2)
    if G.is_valid(y1) and G.is_valid(y1):
        return True
    else:
        print("not valid")
        return False

class AuthService(zkp_auth_pb2_grpc.AuthServicer):
    def Register(self, request, context):
        print("user:", request.user)

        print("y1:\n", request.y1, "\ny2:\n", request.y2)

        username_fname = request.user+".txt"
        username_fpath = os.path.join(USERS_DIR,username_fname)
        if os.path.exists(username_fpath):
            print("ERROR: username " + request.user + " already exists.")
            return zkp_auth_pb2.RegisterResponse(status=ERR_USER_EXISTS)
        if not verify_register_request(request.y1,request.y2):
            print("ERROR: invalid points")
            return zkp_auth_pb2.RegisterResponse(status=ERR_INVALID_POINTS)
        server_store_login_params(username_fpath, request.user, request.y1, request.y2)
        # Handle Register request
        return zkp_auth_pb2.RegisterResponse(status=200)

    def CreateAuthenticationChallenge(self, request, context):
        print("user:", request.user)
        print("r1:", request.r1)
        print("r2:", request.r2)
        username_fname = request.user+".txt"
        reg_params_exist, reg_username, reg_y1, reg_y2 = server_load_reg_params(os.path.join(USERS_DIR,username_fname))
        if not reg_params_exist or reg_username != request.user:
            print("ERROR: user register parameters do not exist for user: " + request.user)
            return zkp_auth_pb2.AuthenticationChallengeResponse(auth_id=str(0), c=0)
        print("parameters loaded")

        y1 = gmpy2.mpz(reg_y1)
        y2 = gmpy2.mpz(reg_y2)
        r1 = gmpy2.mpz(request.r1)
        r2 = gmpy2.mpz(request.r2)
        nonce = int(server_get_random_nonce())
        # print("(nonce, SESSIONS_DIR)", nonce, SESSIONS_DIR)
        # session_fpath = os.path.join(SESSIONS_DIR,str(nonce))
        session_fpath = str(nonce)
        print("Storing session with nonce: " + str(nonce) + " at " + session_fpath)
        server_store_session(session_fpath, str(y1), str(y2), str(r1), str(r2))
        print("Stored session with nonce: ", nonce)
        # Handle CreateAuthenticationChallenge request
        return zkp_auth_pb2.AuthenticationChallengeResponse(auth_id=str(nonce), c=0)


    def VerifyAuthentication(self, request, context):
        print("nonce: ", request.auth_id)
        print("proof: ", request.s)
        try:
            print("Loading session ", request.auth_id)
            session_exists, reg_y1, reg_y2, eph_r1, eph_r2 =server_load_session(request.auth_id)
            if os.path.exists(request.auth_id):
                print("Removing session file.")
                os.remove(request.auth_id)
            if not session_exists:
                print("ERROR: session does not exist")
                return zkp_auth_pb2.AuthenticationAnswerResponse(session_id="0")
            print("Nonce file found")

            y1 = gmpy2.mpz(reg_y1)
            y2 = gmpy2.mpz(reg_y2)
            r1 = gmpy2.mpz(eph_r1)
            r2 = gmpy2.mpz(eph_r2)
            c = gmpy2.mpz(request.auth_id)
            s = gmpy2.mpz(request.s)
            accept = server_verify_proof(y1, y2, r1, r2, c, s)
            print("accept ", accept)
            if not accept:
                print("Proof doesn't verify.")
                return zkp_auth_pb2.AuthenticationAnswerResponse(session_id="0")

            # Handle VerifyAuthentication request
            sid = server_generate_session_id()
            print("session id", sid)
            return zkp_auth_pb2.AuthenticationAnswerResponse(session_id=str(sid))
        except:
            print("ERROR: exception reached.")
            return zkp_auth_pb2.AuthenticationAnswerResponse(session_id="0")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    zkp_auth_pb2_grpc.add_AuthServicer_to_server(AuthService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("Server started, listening on port 50051...")
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == '__main__':
    serve()
