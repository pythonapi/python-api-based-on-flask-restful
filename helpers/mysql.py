'''
Connects to the MySQL database.

Pypi documentation: https://pypi.org/project/PyMySQL/
PIP PyMySQL documentation: https://pymysql.readthedocs.io/en/latest/
'''
import pymysql.cursors
from config import config

class Mysql():
    def __init__(self):
        # Connect to the database
        self.connection = pymysql.connect(host=config['database']['mysql']['host'],
                                         user=config['database']['mysql']['user'],
                                         password=config['database']['mysql']['password'],
                                         db=config['database']['mysql']['db'],
                                         charset='utf8mb4',
                                         cursorclass=pymysql.cursors.DictCursor,
                                         autocommit=False)

    def open(self):
        '''
        Checks if the connection to the database is open.

        Returns
        ----------
        Boolean
        '''
        return self.connection.open

    def close(self):
        '''
        Close database connetion.
        '''
        self.connection.close()

    def execute(self, sql, parameters = ()):
        '''
        Execute a general request - Insert, Update, Delete.

        Parameters
        ----------
        sql : string
        parameters : set
        '''
        with self.connection.cursor() as cursor:
            cursor.execute(sql, parameters)
            self.lastrowid = cursor.lastrowid
        self.connection.commit()
        return self.lastrowid

    def execute_select(self, sql, parameters = ()):
        '''
        Execute select.

        Parameters
        ----------
        sql : string
        parameters : set

        Returns
        ----------
        List
        '''
        with self.connection.cursor() as cursor:
            cursor.execute(sql, parameters)
            return cursor.fetchall()

    def execute_bulk(self, sql, parameters = ()):
        '''
        Execute a general bulk request - Insert, Update, Delete.

        Parameters
        ----------
        sql : string
        parameters : set
        '''
        with self.connection.cursor() as cursor:
            cursor.execute(sql, parameters)

    def commit(self):
        '''
        Commits a bulk requests.
        '''
        self.connection.commit()

    def last_inserted_id(self):
        '''
        Returns the last inserted id.
        '''
        return self.lastrowid
