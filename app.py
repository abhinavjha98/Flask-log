from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
import os
from flask_wtf import Form
import urllib.request
from flask_wtf.file import FileField
import csv
import mysql.connector as ms
from werkzeug.utils import secure_filename
from flask import send_file
import pandas as pd
import mysql.connector
import pyrebase
from firebase import firebase


app = Flask(__name__)

config = {
	"apiKey": "AIzaSyBbBTmLbB76DM8ycI8T3jPwQfmnDDMWWMc",
    "authDomain": "logs-analysis-17e0d.firebaseapp.com",
    "databaseURL": "https://logs-analysis-17e0d-default-rtdb.firebaseio.com",
    "projectId": "logs-analysis-17e0d",
    "storageBucket": "logs-analysis-17e0d.appspot.com",
    "messagingSenderId": "645817396345",
    "appId": "1:645817396345:web:83b8e4a76a5a6017bab8a8",
    "measurementId": "G-VK8J18ELM0"
}

FBConn = firebase.FirebaseApplication('https://logs-analysis-17e0d-default-rtdb.firebaseio.com/')

firebase = pyrebase.initialize_app(config)
storage = firebase.storage()

@app.route('/')
def hello():
    data = pd.read_csv('datasets/Firewall_logs.csv')
    data_sort_value = data.groupby(['dist-ip'])['dist-ip'].count().sort_values(ascending=False)
    df = data_sort_value.to_frame()
    df = df.rename(columns = {'dist-ip':'Count'})
    df_r = df.reset_index()
    ip_address = []
    count = []
    for i in range(len(df_r)):
        if i < 5:
            ip_address.append(df_r.loc[i,'dist-ip'])
            count.append(df_r.loc[i,'Count'])
    print(ip_address)

    start_date = data['date'].iloc[0] + " " + data['time'].iloc[0]
    end_date = data['date'].iloc[-1] + " " + data['time'].iloc[-1]
    protocol = data['protocol'].nunique()
    index = data.index
    nr = len(index)
    return render_template("index.html",distIP=zip(ip_address,count),start_date=start_date,end_date=end_date,protocol=protocol,nr=nr)

@app.route('/chart')
def chart():
    
    return render_template("chart.html")
@app.route('/createfirewalldataset', methods=["GET", "POST"])

def index():
    data = pd.read_csv('datasets/Log.csv')
    print(data)
    fl_data = pd.DataFrame(columns=['date','time','action','protocol','src-ip','dist-ip','size','tcpflags','tcpsyn','tcpack','tcpwin','icmptype','icmpcode','path'])
    for i in range(len(data)): 
        firewall_log = data['Log analysis'][i]
        flog = firewall_log.split(" ")
        if len(flog) ==17:
            dg = flog[4].split(".")
            if(dg[0].isdigit()):
                fl_data.loc[i,'date'] = flog[0] 
                fl_data.loc[i,'time'] = flog[1]
                fl_data.loc[i,'action'] = flog[2]
                fl_data.loc[i,'protocol'] = flog[3]
                fl_data.loc[i,'src-ip'] = flog[4]
                fl_data.loc[i,'dist-ip'] = flog[5]
                fl_data.loc[i,'size'] = flog[6]
                fl_data.loc[i,'tcpflags'] = flog[7]
                fl_data.loc[i,'tcpsyn'] = flog[8]
                fl_data.loc[i,'tcpack'] = flog[9]
                fl_data.loc[i,'tcpwin'] = flog[10]
                fl_data.loc[i,'icmptype'] = flog[11]
                fl_data.loc[i,'icmpcode'] = flog[12]
                fl_data.loc[i,'path'] = flog[16]
                print(firewall_log)
    fl_data.to_csv('datasets/Firewall_logs.csv')
    return "Done"

@app.route('/savedatatofb', methods=["GET", "POST"])
def savedata():
    data = pd.read_csv('datasets/Firewall_logs.csv')
    for ind in data.index:
        data_to_upload = {
                'Date': str(data['date'][ind]),
                'Time': str(data['time'][ind]),
                'Action': str(data['action'][ind]),
                'Protocol': str(data['protocol'][ind]),
                'Src-IP': data['src-ip'][ind],
                'Dist-IP': data['dist-ip'][ind],
                'Size': str(data['size'][ind]),
                'TcpFlags':str( data['tcpflags'][ind]),
                'TcpSyn': str(data['tcpsyn'][ind]),
                'Tcpack': str(data['tcpack'][ind]),
                'Tcpwin': str(data['tcpwin'][ind]),
                'IcmpType': str(data['icmptype'][ind]),
                'IcmpCode': data['icmpcode'][ind],
                'Path': data['path'][ind],
                }
        result = FBConn.post('/firewall_log/', data_to_upload)

    return data_to_upload

if __name__ == '__main__':
    app.run(debug=True)