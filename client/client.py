from doctest import master
import menu
import requests
from backports.pbkdf2 import pbkdf2_hmac
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import Padding 
from Cryptodome.Hash import HMAC
from time import sleep
from flask import Flask, render_template, request , url_for , redirect ,flash,send_file

main = Flask(__name__)




url = "http://127.0.0.1:8000/"
token = None
master_key = None


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token
    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r
@main.route("/")
def home():
    return render_template("zkp.html")


@main.route("/logins",methods=["POST","GET"])
def logines():
      return render_template("login.html")

@main.route("/registers",methods=["POST","GET"])
def registers():
      return render_template("reg.html")
  
@main.route("/landing",methods=["POST","GET"])
def land():
      return render_template("backend/index.html")
    

@main.route("/logined",methods=['GET','POST'])
def logined():
    em1=request.form.get("nm")
    pw1=request.form.get("pw")
    val1=Login(em1,pw1)
    if val1 == 0:
        # flash("you are successfuly logged in")  
        return redirect(url_for('land'))  
        
    else:
        return  render_template('login.html')


@main.route("/registered",methods=['GET','POST'])
def registered():
    nm1=request.form.get("nm")
    em1=request.form.get("em")
    pw1=request.form.get("pw")
    val1=Register(nm1,em1,pw1)
    if val1 == 0:
        return render_template('zkp.html')
    else:
        return  render_template('reg.html')


@main.route("/uploads",methods=['GET','POST'])
def uploads():
    ups = request.form.get("up")
    val5=UploadFile(ups)
    if val5 == 1:
        
        return render_template("backend/index.html",shows='Smething went wrong')
    elif val5 ==0:
        flash("Please login")
        return render_template("backend/index.html",shows='Pleasesses login')
    
    else:
        
        return render_template("backend/index.html",shows=val5)


@main.route("/down",methods=['GET','POST'])
def down():
    global val8
    dns = request.form.get("dn")
    val8=GetFileById(dns)
    if val8 == 0:
        return render_template("backend/index.html",posts='Please login')
        
    elif val8 ==1:
        
        return render_template("backend/index.html",posts='Invalid file id')
    
    elif val8 ==3:
        
        return render_template("backend/index.html",posts='INVALID HMAC ,FILE HAS BEEN MODIFIED')
    else:
        
        return render_template("backend/index.html",posts=val8)

@main.route('/download')
def download_file():
    p=val8
    if val8== 0:
        return render_template("login.html")
    else:
        return send_file(p,as_attachment=True)
        


def Login(em,pw):
    global master_key;
    global token;
    val2 = 0
    email = em
    password = pw
    resp = requests.get(url + "users/get_salt",params={"email":email})
    # if resp.status_code == 404:
    #     val2=1
        # print("User does not exist",val2)
       
        
    salt = bytes.fromhex(resp.text.strip('"'))
    master_and_derived_key = pbkdf2_hmac("sha256","{}:{}".format(email,password).encode(),salt,50000,32)
    derived_key = master_and_derived_key[:len(master_and_derived_key)//2]
    master_key_enc_key = master_and_derived_key[len(master_and_derived_key)//2:]
    crypt = AES.new(master_key_enc_key,AES.MODE_CBC)
    resp = requests.post(url + "users/login",json={"email":email,"derived_key":derived_key.hex()})
    if resp.status_code in [404,403]:
        val2=1
        # print("Invalid credentials",val2)
        
   
    token = resp.json()["access_token"]
    encrypted_master_key = resp.json()["encrypted_master_password"]
    master_key = crypt.decrypt(bytes.fromhex(encrypted_master_key))
    print("login sucesss",val2)
    
    return val2
    
        
    

    
def Register(nm,em,pw):
    global master_key;
    global token;
    val3=0
    name = nm
    email = em
    password = pw
    salt = get_random_bytes(16)
    master_key = get_random_bytes(32)
    master_and_derived_key = pbkdf2_hmac("sha256","{}:{}".format(email,password).encode(),salt,50000,32)
    derived_key = master_and_derived_key[:len(master_and_derived_key)//2]
    master_key_enc_key = master_and_derived_key[len(master_and_derived_key)//2:]
    crypt = AES.new(master_key_enc_key,AES.MODE_CBC)
    encrypted_master_key = crypt.encrypt(master_key)
    resp = requests.put(url + "users/register",json={"email":email,"derived_key":derived_key.hex(),"name":name,"encrypted_master_password":encrypted_master_key.hex(),"salt":salt.hex()})
    if resp.status_code != 200:
        # print("Invalid input")
        # print(resp.json())
        val3=1
        
    print("Successfully created user",val3)
    return val3
  


def UploadFile(ups):
    if token == None:
        k="Please login"
        k1=0
        return k1
    file_path = ups
    with open(file_path,"rb") as file:
        file_name = file_path.split("/")[-1]
        file_key = get_random_bytes(32)
        crypt = AES.new(file_key,AES.MODE_ECB)
        key_crypt = AES.new(master_key,AES.MODE_ECB)
        encrypted_file_key = key_crypt.encrypt(file_key)
        encrypted_data = crypt.encrypt(Padding.pad(file.read(),16))
        hmac = HMAC.new(master_key,encrypted_data).hexdigest()
        temp = open("/tmp/" + file_name,"wb")
        temp.write(encrypted_data)
        temp.close()
        temp = open("/tmp/" + file_name,"rb")
        resp = requests.put(url + "files/upload",auth=BearerAuth(token),files={"encrypted_file":temp},data={"encrypted_file_key":encrypted_file_key.hex(),"hmac":hmac})
        
        
        temp.close()
        if resp.status_code != 200:
            u="Something went wrong"
            u1=1
            return u1
        file_id = resp.json()["file_id"]
        
        return file_id
       

def GetFileById(dns):
    if token == None:
        print("Please login")
        k=0
        return k
        
        
    file_id = dns
    resp = requests.get(url + "files/{}".format(file_id),auth=BearerAuth(token))
    if resp.json().get("status") == "error":
        print("Invalid file id")
        k=1
        return k
    file_name = resp.json()["file_name"]
    encrypted_file_key = bytes.fromhex(resp.json()["encrypted_file_key"])
    dirty_hmac = bytes.fromhex(resp.json()["hmac"])
    key_crypt = AES.new(master_key,AES.MODE_ECB)
    file_key = key_crypt.decrypt(encrypted_file_key)
    resp = requests.get(url + "files/{}/download".format(file_id),auth=BearerAuth(token))
    crypt = AES.new(file_key,AES.MODE_ECB)
    # flash("Decrypting {}...".format(file_name))
    with open(file_name,"wb") as file:
        hmac = HMAC.new(master_key,resp.content)
        try:
            hmac.verify(dirty_hmac)
        except:
            print("INVALID HMAC ,FILE HAS BEEN MODIFIED")
            k=3
            return k
        file_data = Padding.unpad(crypt.decrypt(resp.content),16)
        file.write(file_data)
    k="{}".format(file_name)
    return k 
    
   

if __name__ == "__main__":
    main.run(debug=True)      

# print("Welcome to Encrypt EveryWhere Client")
# splash_options = [("Login",Login),
#             ("Register",Register),
#             ("Upload",UploadFile),
#             ("Download",GetFileById),
#             ]
# splash_menu = menu.Menu(title="Welcome to Encrypt EveryWhere Client",options=splash_options)
# splash_menu.open()

