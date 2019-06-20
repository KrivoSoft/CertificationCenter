#!/usr/bin/env python3
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

# Привязка функции к URL-адресу
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='Home', all_cert = all_cert)
    
    
@app.route('/all_certificates')
def all_certificates():
    return render_template('all_certificates.html', title='all_certificates', all_cert = all_cert)


# Поиск всех сертификатов в директории
def ShowFiles():
    p = Path('/home/marka/Загрузки/Folder/').glob('*.crt')
    files = [x for x in p if x.is_file()]
    return files


def FilesToCert(list_of_files):
    for certificate in list_of_files:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(str(certificate)).read())
        subject = cert.get_subject().CN
        issuer = cert.get_issuer().CN
        
        time_start = cert.get_notBefore()
        time_start = str(time_start, 'utf-8')
        time_end = cert.get_notAfter()
        time_end = str(time_end, 'utf-8')
        # Приведение строковой даты к виду
        # Изначальный формат даты: YYYYMMDDhhmmssZ
        # Преобразование к виду: DD-MM-YYYY-hh-mm
        time_start = time_start[6:8] + '-' + time_start[4:6] + '-' + time_start[:4] + '-' + time_start[8:10] + '-' + time_start[10:12]
        time_end = time_end[6:8] + '-' + time_end[4:6] + '-' + time_end[:4] + '-' + time_end[8:10] + '-' + time_end[10:12]
        all_cert.append(Certificate(time_start, time_end, subject, issuer))
            
    
class Certificate():
    # Создание нового сертифката и добавление его в список всех сертификатов
    def __init__(self, time_start, time_end, subject, issuer):
        self.time_start = datetime.strptime(time_start, "%d-%m-%Y-%H-%M")
        self.time_end = datetime.strptime(time_end, "%d-%m-%Y-%H-%M")
        self.subject = subject
        self.issuer = issuer           
    
    
    # Проверка на валидность сертификата
    def IsValid(cert):
        now = datetime.now()
        if (cert.time_end >= now) & (cert.time_start <= now):
            return True
        else:
            return False


all_cert = []    
all_cert.append(Certificate('01-01-1990-00-00', '01-01-2010-00-00', 'personal-site.com', 'CertCenter'))
all_cert.append(Certificate('01-09-2019-00-00', '01-01-2020-00-00', 'big-company.com', 'CertCenter'))
all_cert.append(Certificate('01-01-2018-00-00', '01-09-2019-00-00', 'my-site.com', 'CertCenter'))
MyCert = ShowFiles()
FilesToCert(MyCert)
