#!/usr/bin/python2.7
import sys
import sqlite3

###############################################################################
#                                                                             #
# Written By: sanjayc                                                         #
#                                                                             #
# Purpose: This class is just so that we can easily connect to a sqlite3      #
#          database in python. We import this in all our files that work      #
#          with sqlite3 databases in python                                   #
#                                                                             #
# Usage: from insert_db import InsertDB                                       #
#        ins_db = InsertDB(<database_path>)                                   #
#                                                                             #
###############################################################################


class InsertDB:
    def __init__(self, db_file):
        self.db_file = db_file
        
    def create_connection(self):
        try:
            conn = sqlite3.connect(self.db_file)
            return conn
        except Error as e:
            print(e) 
        return None

