## Synopsis

This is a multi-user blog web application that uses Python and Google App Engine along with Jinja templates to produce its functionality. This is the third project for the Udacity Full Stack Web Development course.

## Run
To run locally:

You will need to install the [Google Cloud SDK](https://cloud.google.com/appengine/docs/python/download) to run Google App Engine Python applications locally.

Once you have it installed, using the command line or terminal, navigate to the location of the directory containing the app.yaml file and run "dev_appserver.py blog" where "blog" is the name of the directory.

Now open an internet browser and navigate to "localhost:8080".

To view the hosted site, go to this link: [Multi-User Blog](https://sodium-wall-146901.appspot.com/) to open my blog site.

The homepage is just a blank page with a nav bar at the top. Click on **Signup** to create a new user or click on **Login** if you have already signed up. Otherwise, click on **Multi User Blog** or **Browse** to view all submitted blog posts.

If you own a blog post, you can **edit** or **delete** it. Other than that, any logged in user can **comment**, **like** or **dislike**. Any visitor can view a blog post and its comments.

A signed in user can create a new blog post by clicking **New Post** in the nav bar.

Click on **Logout** if you wish to log out.
