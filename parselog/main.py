from collections import OrderedDict
import re
from datetime import datetime
from sqlalchemy import Table, Column, Integer, String, MetaData, create_engine,select
from sqlalchemy import DateTime as SqlDateTime


class ParseLog:

    def __init__(self, logfile_path):
        """
        Initialize the parser object.
        Creates the messages table and intializes the database connection
        :param logfile_path: the path to the logfile to read
        """
        self.logfile_path = logfile_path
        self.engine = create_engine('sqlite:///:memory:', echo=True)
        self.conn = self.engine.connect()
        self.metadata = MetaData()
        # %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"
        self.regex = r'^(\S+) (\S+) (\S+) \[(.+)\] "(.+)" (\S+) (\S+) "(.+)" "(.+)"'
        d = OrderedDict()

        self.columns = OrderedDict([
            ('hostname', String),
            ('log_name', String),
            ('remote_user', String),
            ('timestamp', SqlDateTime),
            ('first_line', String),
            ('final_status', Integer),
            ('bytes', Integer),
            ('referrer', String),
            ('user_agent', String)
        ])
        self.messages_table = Table(
            'messages', self.metadata,
            Column('id', Integer, primary_key=True),
            *[Column(name, clazz) for name, clazz in self.columns.items()]

        )

    def initialize(self):
        """
        create the tables
        :return:
        """
        self.metadata.create_all(self.engine)

    def parse(self):
        """
        parse the log file that was passed in
        :return:
        """
        file = open(self.logfile_path, 'r')
        [self.parse_message_and_insert(line) for line in file]

    def parse_message_and_insert(self, line):
        """
        parse a single line and insert to db
        :param line: a single line from the access log
        :return:
        """
        match = re.search(self.regex, line)
        if match:
            i = 1
            values = dict()
            for name, clazz in self.columns.items():
                values[name] = self.parse_for_type(match.group(i), clazz)
                i += 1
            ins = self.messages_table.insert().values(**values)
            self.conn.execute(ins)

    def parse_for_type(self, value, clazz):
        """
        get a raw value into the correct data type
        :param value:  raw data
        :param clazz:  the sqlalchemy data type
        :return:       the value in the correct type
        """
        if clazz == SqlDateTime:
            return datetime.strptime(value, '%d/%b/%Y:%H:%M:%S %z')
        elif clazz == Integer:
            return int(value)
        else:
            return value

    def dump_db(self):
        """
        prints out the contents of the database
        :return:
        """
        s = select([self.messages_table])
        result = self.conn.execute(s)
        for row in result:
            print(row)

p = ParseLog('samples/access.log')
p.initialize()
p.parse()
p.dump_db()