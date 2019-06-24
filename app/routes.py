#!/usr/bin/env python3
# pycryptodome 3.4.3
#
#  routes.py
#  
#  Copyright 2019 Marka <marka@evil>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#

from datetime import datetime
from flask import render_template
from app import app
from pathlib import Path
from OpenSSL import crypto

path_to_public_cert = '/home/marka/Загрузки/Folder/'
path_to_trusted_cert = '/home/marka/Загрузки/Folder/trusted_cert/ca.crt'


@app.route('/')
@app.route('/index')
def index():
    """Привязка функции к URL-адресу."""
    return render_template('index.html', title='Home', all_cert = all_cert)
    
    
@app.route('/all_certificates')
def all_certificates():
    """Привязка функции к URL-адресу."""
    return render_template('all_certificates.html', title='all_certificates', all_cert = all_cert)


def search_for_certificates(path_to_folder):
    """Поиск всех сертификатов в директории."""
    p = Path(path_to_folder).glob('*.crt')
    files = [x for x in p if x.is_file()]
    return files


def info_about_cert(certificate):
    """Извлечение информации о сертификате."""
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(str(certificate)).read())
    subject = cert.get_subject().CN
    issuer = cert.get_issuer().CN
    
    time_start = cert.get_notBefore()
    time_start = str(time_start, 'utf-8')
    time_start = datetime.strptime(time_start, "%Y%m%d%H%M%SZ")
    time_end = cert.get_notAfter()
    time_end = str(time_end, 'utf-8')
    time_end = datetime.strptime(time_end, "%Y%m%d%H%M%SZ")
    return time_start, time_end, subject, issuer


def check_certificate(doubtful_certificate, trusted_cert):
    '''Подтверждение сертификата'''
    
    # Загружаем доверенный и проверяемый сертификаты
    doubtful_certificate = open(str(doubtful_certificate)).read()
    doubtful_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, doubtful_certificate)    
    open_key = open(trusted_cert).read()
    trusted_cert = Path(trusted_cert)
    trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open_key)
    
    store = crypto.X509Store()
    store.add_cert(trusted_cert)
    store_ctx = crypto.X509StoreContext(store, doubtful_certificate)
    try:
        result = store_ctx.verify_certificate()
        return True
    except crypto.X509StoreContextError as e:
        return False
        
    
class Certificate():
    def __init__(self, time_start, time_end, subject, issuer):
        """Создание нового сертифката."""
        if type(time_start) is str:
            self.time_start = datetime.strptime(time_start, "%d-%m-%Y-%H-%M")
        else:
            self.time_start = time_start
        if type(time_end) is str:
            self.time_end = datetime.strptime(time_end, "%d-%m-%Y-%H-%M")
        else:
            self.time_end = time_end          
        self.subject = subject
        self.issuer = issuer           
        
    def is_valid(cert):
        """Проверка срока действия сертификата."""
        now = datetime.now()
        if (cert.time_end >= now) & (cert.time_start <= now):
            return True
        else:
            return False


all_cert = []

certs_in_directory = search_for_certificates(path_to_public_cert)
for one_cert in certs_in_directory:
    time1, time2, who_to, who_from = info_about_cert(one_cert)
    if check_certificate(one_cert, path_to_trusted_cert) == True:
        all_cert.append(Certificate(time1, time2, who_to, who_from))
