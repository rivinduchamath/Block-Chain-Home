# Created on Sun May 26 03:22:09 2019
# @author: Rivindu Wijayarathna


import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String ,DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import random,string

 
Base = declarative_base()

class UPCNumbers(Base):
    
    __tablename__ = 'upcnumbers'
    id = Column(Integer, primary_key=True)
    
    def __init__(self, id):
        self.id = id

        

class LicenceIds(Base):
    
    __tablename__ = 'licenceids'
    id = Column(String(250), primary_key=True)
    
    def __init__(self, id):
        self.id = id

class AccountDetails(Base):
    
    __tablename__ = 'accountdetails'
    id = Column(String(250), primary_key=True)
    name = Column(String(250),nullable=False)
    role = Column(String(250),nullable=False)
    manufacturer_license_id = Column(String(250),nullable = True)

    def __init__(self, id, name, role, manufacturer_license_id):
        self.id = id
        self.name = name
        self.role = role
        self.manufacturer_license_id = manufacturer_license_id