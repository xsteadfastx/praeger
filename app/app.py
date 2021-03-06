from flask import Flask, render_template, redirect, flash, url_for, session
from flask.ext.login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask.ext.mongoengine import MongoEngine
from flask_bootstrap import Bootstrap
from flask_wtf import Form
from operator import itemgetter
from passlib.hash import sha256_crypt
from wtforms import TextField, PasswordField
from wtforms.validators import Required, EqualTo, Email, Regexp
import datetime
import requests

from config import *


app = Flask(__name__)


app.secret_key = SECRET_KEY
app.config['SITENAME'] = SITENAME
app.config['MONGODB_SETTINGS'] = MONGODB_SETTINGS
db = MongoEngine(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)


def today():
    ''' simply returns today date '''
    return datetime.datetime.utcnow().strftime('%Y/%m/%d')


def create_datetime_object(date):
    ''' creates datetime object out of string '''
    return datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')


def get_football_data():
    r = requests.get(API_BASE_URL + '/event/world.2014/rounds')
    rounds = r.json()
    positions = []
    for item in rounds['rounds']:
        positions.append(item['pos'])
    matches = []
    for position in positions:
        r = requests.get(
            API_BASE_URL + '/event/world.2014/round/%i' %
            position)
        for match in r.json()['games']:
            matches.append(match)
    matches = sorted(matches, key=itemgetter('play_at'))
    return matches


def get_rounds():
    ''' getting a json with a rounds overview '''
    r = requests.get(
        API_BASE_URL + '/event/world.2014/rounds')
    return r.json()


def get_round(round_number):
    ''' getting a specific round json '''
    r = requests.get(
        API_BASE_URL + '/event/world.2014/round/%i' %
        round_number)
    return r.json()


def get_teams():
    r = requests.get(API_BASE_URL + '/event/world.2014/teams')
    teams = []
    for team in r.json()['teams']:
        teams.append(team['key'])
    return sorted(teams)


def play_at(round_number, team1, team2):
    round = get_round(round_number)
    for game in round['games']:
        if game['team1_key'] == team1 and game['team2_key'] == team2:
            return create_datetime_object(game['play_at']).strftime('%Y/%m/%d')
        else:
            pass


def get_matches_for_team(team_key):
    data = get_football_data()
    matches = []
    for game in data:
        if game['team1_key'] == team_key or game['team2_key'] == team_key:
            matches.append(game)
    return matches


def matchday(date):
    data = get_football_data()
    matches = []
    for match in data:
        if create_datetime_object(match['play_at']).strftime('%Y/%m/%d') == date:
            matches.append(match)
    return matches


def team_key_to_title(code):
    data = get_football_data()
    keys_to_titles = {}
    for i in data:
        keys_to_titles[i['team1_key']] = i['team1_title']
        keys_to_titles[i['team2_key']] = i['team2_title']
    return keys_to_titles[code]


def same_score(real_score, bet_score):
    return real_score == bet_score


def same_goal_difference(real_score, bet_score):
    return real_score[0] - real_score[1] == bet_score[0] - bet_score[1]


def right_winner(real_score, bet_score):
    # winner 1
    if real_score[0] < real_score[1] and bet_score[0] < bet_score[1]:
        return True
    # winner 2
    if real_score[0] > real_score[1] and bet_score[0] > bet_score[1]:
        return True
    # No winner, or wrong winner
    return False


def score_check(real_score, bet_score):
    ''' checks realm score and the bet and return the points '''
    if same_score(real_score, bet_score):
        return 5

    if same_goal_difference(real_score, bet_score):
        return 4

    if right_winner(real_score, bet_score):
        return 3

    return 0


@login_manager.user_loader
def load_user(userid):
    return UserAuth(uid=userid)


class UserAuth(UserMixin):

    def __init__(self, uid=None, password=None, active=True):
        self.id = uid
        self.active = active

    def get_user(self, username):
        try:
            user = User.objects(username=username).first()
            if user:
                self.username = user.username
                self.password = user.password
                return self
            else:
                return None
        except:
            return None


class User(db.Document):
    username = db.StringField(min_length=3, max_length=20, required=True)
    password = db.StringField(min_length=5, max_length=255, required=True)
    first_name = db.StringField(max_length=255, required=True)
    last_name = db.StringField(max_length=255, required=True)
    email = db.StringField(min_length=3, max_length=30, required=True)


class Match(db.Document):
    team1 = db.StringField(min_length=3, max_length=30, required=True)
    team2 = db.StringField(min_length=3, max_length=30, required=True)
    round = db.IntField(required=True)
    bets = db.ListField(db.EmbeddedDocumentField('Bet'))


class Bet(db.EmbeddedDocument):
    username = db.StringField(min_length=3, max_length=20, required=True)
    score1 = db.IntField(required=True)
    score2 = db.IntField(required=True)


class LoginForm(Form):
    username = TextField('Username', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])


class RegisterForm(Form):
    username = TextField('Username', validators=[Required()])
    password = PasswordField('Password', validators=[
        Required(),
        EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')
    first_name = TextField('First Name', validators=[Required()])
    last_name = TextField('Last Name', validators=[Required()])
    email = TextField('Email', validators=[Required(), Email()])


class SettingsForm(Form):
    password = PasswordField('Password', validators=[
        Required(),
        EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')
    first_name = TextField('First Name', validators=[Required()])
    last_name = TextField('Last Name', validators=[Required()])
    email = TextField('Email', validators=[Required(), Email()])


class MatchForm(Form):
    score1 = TextField('', validators=[Required(), Regexp('^[0-9]+$')])
    score2 = TextField('', validators=[Required(), Regexp('^[0-9]+$')])


@app.context_processor
def utility_processor():
    def get_date(date):
        return create_datetime_object(date).strftime('%Y%m%d')

    def get_time(date):
        return create_datetime_object(date).strftime('%H:%M')

    def get_round_data(round_number):
        return get_round(round_number)

    def get_today():
        return datetime.date.today()

    def get_play_at(date):
        return create_datetime_object(date).date()
    return dict(get_date=get_date,
                get_time=get_time,
                get_round=get_round_data,
                get_today=get_today,
                get_play_at=get_play_at)


@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if 'user_id' in session:
        return redirect(url_for('loggedin'))
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user_obj = UserAuth(uid=username, password=password)
        user = user_obj.get_user(username)
        if user and sha256_crypt.verify(password, user.password) and user.is_active():
            if login_user(user, remember=True):
                flash('Logged in', 'success')
                return redirect(url_for('loggedin'))
            else:
                flash('unable to log in', 'danger')
        else:
            flash('unable to log in', 'danger')
    return render_template('index.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            User(username=form.username.data,
                 password=sha256_crypt.encrypt(form.password.data),
                 first_name=form.first_name.data,
                 last_name=form.last_name.data,
                 email=form.email.data).save()
            flash('Registered successfully', 'success')
            return redirect(url_for('index'))
        except Exception:
            flash('Failed to register', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html', form=form)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = User.objects(username=current_user.get_id()).first()
    form = SettingsForm(first_name=user.first_name,
                        last_name=user.last_name,
                        email=user.email)
    if form.validate_on_submit():
        try:
            user.first_name = form.first_name.data
            user.last_name = form.last_name.data
            user.email = form.email.data
            user.password = sha256_crypt.encrypt(form.password.data)
            user.save()
            flash('Changed settings successfully', 'success')
            return redirect(url_for('settings'))
        except Exception:
            flash('Failed to change settings', 'danger')
            return redirect(url_for('settings'))
    return render_template('settings.html',
                           rounds=get_rounds(),
                           form=form)


@app.route('/loggedin', methods=['GET', 'POST'])
@login_required
def loggedin():
    matches = matchday(today())
    return render_template('loggedin.html',
                           rounds=get_rounds(),
                           matches=matches,
                           today=today())


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/round/<int:round_number>')
@login_required
def round(round_number):
    round_data = get_round(round_number)
    for game in round_data['games']:
        game['other_bets'] = {}
        # db stuff
        match = Match.objects(
            round=round_data['round']['pos'],
            team1=game['team1_key'],
            team2=game['team2_key']).first()
        # trying to get bets
        try:
            for bet in match.bets:
                if bet.username == current_user.get_id():
                    game['bet_score1'] = bet.score1
                    game['bet_score2'] = bet.score2
                else:
                    game['other_bets'][bet.username] = [bet.score1, bet.score2]
        except:
            pass
        try:
            for bet in match.bets:
                if 'bet_score1' not in game and 'bet_score2' not in game:
                    game['bet_score1'] = None
                    game['bet_score2'] = None
        except:
            game['bet_score1'] = None
            game['bet_score2'] = None

    return render_template('round.html',
                           rounds=get_rounds(),
                           round=round_data)


@app.route('/bet/<int:round_number>-<team1>-<team2>', methods=['GET', 'POST'])
@login_required
def bet(round_number, team1, team2):
    rounds = get_rounds()
    # if the game is today redirect to login page
    if today() == play_at(round_number, team1, team2):
        return redirect('/round/' + str(round))
    # try to get the db object and if not set match to None
    match = Match.objects(
        team1=team1,
        team2=team2,
        round=round_number).first()
    # if match is there check for bets and predefine the matchform
    if match is not None:
        try:
            for bet in match.bets:
                if bet.username == current_user.get_id():
                    form = MatchForm(score1=bet.score1,
                                     score2=bet.score2)
        except:
            pass
    # if form is not defined yet... define it
    if 'form' not in locals():
        form = MatchForm()
    # stuff that happens if data gets submitted
    if form.validate_on_submit():
        # if match doesnt exist... add it to the db
        if match is None:
            match = Match(
                team1=team1,
                team2=team2,
                round=round_number)
        there_is_a_bet = False
        for bet in match.bets:
            if bet.username == current_user.get_id():
                there_is_a_bet = True
                bet.score1 = form.score1.data
                bet.score2 = form.score2.data
        if there_is_a_bet is False:
            bet = Bet(username=current_user.get_id(),
                      score1=form.score1.data,
                      score2=form.score2.data)
            match.bets.append(bet)
        match.save()
        return redirect('/round/' + str(round_number))
    return render_template(
        'bet.html',
        form=form,
        rounds=rounds,
        round=round,
        team1=team_key_to_title(team1),
        team2=team_key_to_title(team2))


@app.route('/team/<team_key>')
@login_required
def team(team_key):
    return render_template('team.html',
                           rounds=get_rounds(),
                           teamname=team_key_to_title(team_key),
                           matches=get_matches_for_team(team_key))


@app.route('/score')
@login_required
def score():
    users = User.objects
    matches = Match.objects
    user_score = {}
    for user in users:
        user_score[user.username] = 0
    for match in matches:
        round_data = get_round(match.round)
        for game in round_data['games']:
            if game['team1_key'] == match.team1 and game['team2_key'] == match.team2:
                real_score = [game['score1'], game['score2']]
            else:
                pass
        try:
            for bet in match.bets:
                if None not in real_score:
                    user_score[
                        bet.username] += score_check(real_score, [bet.score1, bet.score2])
                else:
                    pass
        except:
            pass
    return render_template(
        'score.html',
        rounds=get_rounds(),
        user_score=sorted(user_score.iteritems(),
                          key=itemgetter(1),
                          reverse=True))


@app.route('/rules')
@login_required
def rules():
    return render_template(
        'rules.html',
        rounds=get_rounds())


if __name__ == '__main__':
    app.run(debug=True)
