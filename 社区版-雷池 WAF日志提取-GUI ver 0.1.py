import sys
import os.path
import requests
import csv
import configparser
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QHBoxLayout, QTextEdit, QMessageBox

CONFIG_FILE = "config.ini"
CSRF_PATH = "/api/open/auth/csrf"
LOGIN_PATH = "/api/open/auth/login"
RECORDS_PATH = "/api/open/records"
class MainWindow(QWidget):
    HOST = None

    headers = {"Authorization": None}

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Host输入框
        host_layout = QHBoxLayout()
        host_label = QLabel('HOST请求地址:')
        self.host_edit = QLineEdit()
        host_layout.addWidget(host_label)
        host_layout.addWidget(self.host_edit)

        # 配置文件路径输入框
        config_layout = QHBoxLayout()
        config_label = QLabel('配置文件路径:')
        self.config_edit = QLineEdit()
        config_layout.addWidget(config_label)
        config_layout.addWidget(self.config_edit)

        # 过滤URL输入框
        filter_layout = QHBoxLayout()
        filter_label = QLabel('过滤URL:')
        self.filter_edit = QLineEdit()
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_edit)

        # 导出日志按钮
        self.export_button = QPushButton('导出日志')
        self.export_button.clicked.connect(self.export_clicked)

        # 程序运行日志框
        self.log_textedit = QTextEdit()
        self.log_textedit.setReadOnly(True)

        layout.addLayout(host_layout)
        layout.addLayout(config_layout)
        layout.addLayout(filter_layout)
        layout.addWidget(self.export_button)
        layout.addWidget(self.log_textedit)

        self.setLayout(layout)
    def export_clicked(self):
        self.export_logs()

    def export_logs(self):
        username, password = self.load_config()
        with requests.Session() as session:
            self.login_waf(session, username, password)
            self.query_logs(session, self.filter_edit.text())
            self.log_textedit.append("[Info] 日志已成功导出到 safeline_waf_logs.csv 文件")
        QMessageBox.information(None, "导出完成", "日志已成功导出到 safeline_waf_logs.csv 文件")


    def get_request_response(self, session, path):
        r = session.get(path, headers=self.headers).json()
        if len(r['data']) == 0:
            self.log_textedit.append("[Error] " + r['msg'])
            return None, None
        req_header = r['data']['req_header']
        req_body = r['data']['req_body']
        return req_header, req_body

    def verfiy_jwt(self, ):
        pass
    def login_waf(self, session, username, password):
        host = self.host_edit.text().split("/")[0] + "//" + self.host_edit.text().split("/")[2]
        csrf_token = session.get(host + CSRF_PATH).json()['data']['csrf_token']
        data = {"username": username, "password": password, "csrf_token": csrf_token}
        r = session.post(host + LOGIN_PATH, json=data).json()


        if len(r['data']) == 0:
            self.log_textedit.append("[Error] " + r['msg'])
            return

        self.headers['Authorization'] = "Bearer " + r['data']['jwt']
        session.headers.update({"Authorization": "Bearer " + r['data']['jwt']})
        self.query_logs(session,self.filter_edit.text())

    def query_logs(self, session, url=''):
        waf_host = self.host_edit.text().split("/")[0] + "//" + self.host_edit.text().split("/")[2]
        page_size = 100
        total = float('inf')
        page = 1

        with open('safeline_waf_logs.csv', 'w', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Event_Id', 'Host', 'Website', 'Source IP', 'Reason', 'Request Header', 'Request Body'])

            while (page - 1) * page_size < total:
                params = {'page': page, 'page_size': page_size, 'host': url}
                r = session.get(waf_host + RECORDS_PATH, params=params, headers=self.headers).json()
                if len(r['data']) == 0:
                    self.log_textedit.append("[Error] " + r['msg'])
                    return

                data = r['data']['data']
                total = r['data']['total']

                for item in data:
                    host = item['host']
                    website = item['website']
                    src_ip = item['src_ip'] + "（" + item['province'] + "）"
                    reason = item['reason']
                    event_id = item['event_id']
                    http = self.get_request_response(session ,waf_host + f"/api/open/record/{event_id}")
                    writer.writerow([event_id, host, website, src_ip, reason, http[0], http[1]])

                page += 1
            logout_ = session.post(waf_host+"/api/open/auth/logout",headers=self.headers).json()
            if logout_['data'] != None:
                self.log_textedit.append("[Info] Waf帐号退出不成功，可能会对waf产生影响")
        csvfile.close()

    @staticmethod
    def load_config():
        if not os.path.exists(CONFIG_FILE):
            self.log_textedit.append("[Error] config file not exists!")
            self.log_textedit.append("[Error] Init Config.ini File!")
            with open("config.ini","w+") as f:
                f.write("[account]\nusername=\npassword=")
            f.close()
            return None, None

        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        return config['account']['username'], config['account']['password']


if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.setWindowTitle('社区版-雷池 WAF日志提取-GUI ver 0.1')
    mainWindow.show()
    sys.exit(app.exec_())
