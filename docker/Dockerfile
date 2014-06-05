FROM ubuntu:trusty

# Add 10gen official apt source to the sources list
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10
RUN echo 'deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen' | tee /etc/apt/sources.list.d/10gen.list

# Hack for initctl not being available in Ubuntu
RUN dpkg-divert --local --rename --add /sbin/initctl
#RUN ln -s /bin/true /sbin/initctl

# Install MongoDB
RUN apt-get update
RUN apt-get install mongodb-10gen

# Create the MongoDB data directory
RUN mkdir -p /data/db

# Install git and pip and ssh
RUN apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo "root:praeger" | chpasswd
RUN sed --in-place=.bak 's/without-password/yes/' /etc/ssh/sshd_config
RUN apt-get install -y git
RUN apt-get install -y python-pip
RUN apt-get install -y build-essential python-dev

# Install Ruby and sportdb
RUN apt-get install -y ruby ruby-bundler rake libsqlite3-dev
RUN gem install sportdb
RUN gem install sqlite3 
ADD update-footballdb /etc/cron.daily/update-footballdb
RUN chmod +x /etc/cron.daily/update-footballdb
RUN mkdir /opt/footballdb
RUN mkdir /opt/footballdb/openmundi
RUN mkdir /opt/footballdb/openfootball
RUN git clone https://github.com/openmundi/world.db.git /opt/footballdb/openmundi/world.db
RUN git clone https://github.com/openfootball/world-cup.git /opt/footballdb/openfootball/world-cup
RUN git clone https://github.com/openfootball/national-teams.git /opt/footballdb/openfootball/national-teams
RUN git clone https://github.com/openfootball/build.git /opt/footballdb/openfootball/build
RUN cd /opt/footballdb/openfootball/build && rake build DATA=worldcup2014

# Football.db API
RUN git clone https://github.com/xsteadfastx/sport.db.api.starter.git /opt/footballdb/api
RUN cd /opt/footballdb/api && bundle install
RUN cp /opt/footballdb/openfootball/build/build/football.db /opt/footballdb/api/

# Install praeger
RUN git clone https://github.com/xsteadfastx/praeger.git /opt/praeger
RUN pip install -r /opt/praeger/requirements.txt
RUN pip install gunicorn

# Install and supervisor
RUN apt-get install -y supervisor
RUN mkdir -p /var/log/supervisor

ADD supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 22 27017 8000 9292
CMD ["/usr/bin/supervisord"]
