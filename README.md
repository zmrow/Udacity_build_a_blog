# Udacity Multi User Blog engine
This project is a simple multi-user blog engine created for the Udacity Full Stack Developer Nanodegree.  It allows users to:
- Signup
- Login / Logout
- View blog posts for all users
- Create blog posts of their own (all CRUD operations supported)
- Post comments on other users' posts (all CRUD operations supported)
- Like other users' posts

This project makes use of the awesome [Bootstrap framework](http://getbootstrap.com/).

A current running version [is available here](https://blog-udacity-163416.appspot.com/blog/newpost).

## Quick start

Simple:

- Clone the repo
- Install Google App Engine for python locally using [these instructions](https://cloud.google.com/appengine/docs/standard/python/how-to)
- Navigate to the cloned directory
- Fire up the local dev server (`~/google-cloud-sdk/bin/dev_appserver.py .`)
- Fire up your browser and navigate to `http://localhost:8080/blog`
- Win

## What's what
The repo has quite a few files:

- `main.py`: this is the main entrypoint for the application
- `app.yaml`: this is the main configuration file for Google App Engine
- `static/bootstrap.min.css`: this is the Bootstrap css styles
- `templates/`: this folder contains all the templates for the site

## TODO
- Tests - I've found that things have a tendency to break when you least expect it
- Better User authentication and session support (don't spin my own)
- Support image upload
- Better front end styling
- Tests
- Did I mention tests?
