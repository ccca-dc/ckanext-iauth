.. You should enable this project on travis-ci.org and coveralls.io to make
   these badges work. The necessary Travis and Coverage config files have been
   generated for you.

.. image:: https://travis-ci.org/KatharinaSack/ckanext-iauth.svg?branch=master
    :target: https://travis-ci.org/KatharinaSack/ckanext-iauth

.. image:: https://coveralls.io/repos/KatharinaSack/ckanext-iauth/badge.svg
  :target: https://coveralls.io/r/KatharinaSack/ckanext-iauth

.. image:: https://pypip.in/download/ckanext-iauth/badge.svg
    :target: https://pypi.python.org/pypi//ckanext-iauth/
    :alt: Downloads

.. image:: https://pypip.in/version/ckanext-iauth/badge.svg
    :target: https://pypi.python.org/pypi/ckanext-iauth/
    :alt: Latest Version

.. image:: https://pypip.in/py_versions/ckanext-iauth/badge.svg
    :target: https://pypi.python.org/pypi/ckanext-iauth/
    :alt: Supported Python versions

.. image:: https://pypip.in/status/ckanext-iauth/badge.svg
    :target: https://pypi.python.org/pypi/ckanext-iauth/
    :alt: Development Status

.. image:: https://pypip.in/license/ckanext-iauth/badge.svg
    :target: https://pypi.python.org/pypi/ckanext-iauth/
    :alt: License

=============
ckanext-iauth
=============

.. Represents a collection of all authorization functions
   required by various CCCA-plugins

   Also modifies the rights if the EDITOR role:
   Only modifiy and delete your own dataset

   Parameter in Development/Production.ini:

   ckanext.iauth.editor_modified = true





------------
Requirements
------------

For example, you might want to mention here which versions of CKAN this
extension works with.


------------
Installation
------------

.. Add any additional install steps to the list below.
   For example installing any non-Python dependencies or adding any required
   config settings.

To install ckanext-iauth:

1. Activate your CKAN virtual environment, for example::

     . /usr/lib/ckan/default/bin/activate

2. Install the ckanext-iauth Python package into your virtual environment::

     pip install ckanext-iauth

3. Add ``iauth`` to the ``ckan.plugins`` setting in your CKAN
   config file (by default the config file is located at
   ``/etc/ckan/default/production.ini``).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu::

     sudo service apache2 reload


---------------
Config Settings
---------------

Represents a collection of all authorization functions
   required by various CCCA-plugins

   Also modifies the rights if the EDITOR role:
   Only modifiy and delete your own dataset

   Parameter in Development/Production.ini:

   ckanext.iauth.editor_modified = true



------------------------
Development Installation
------------------------

To install ckanext-iauth for development, activate your CKAN virtualenv and
do::

    git clone https://github.com/KatharinaSack/ckanext-iauth.git
    cd ckanext-iauth
    python setup.py develop
    pip install -r dev-requirements.txt


-----------------
Running the Tests
-----------------

To run the tests, do::

    nosetests --nologcapture --with-pylons=test.ini

To run the tests and produce a coverage report, first make sure you have
coverage installed in your virtualenv (``pip install coverage``) then run::

    nosetests --nologcapture --with-pylons=test.ini --with-coverage --cover-package=ckanext.iauth --cover-inclusive --cover-erase --cover-tests


---------------------------------
Registering ckanext-iauth on PyPI
---------------------------------

ckanext-iauth should be availabe on PyPI as
https://pypi.python.org/pypi/ckanext-iauth. If that link doesn't work, then
you can register the project on PyPI for the first time by following these
steps:

1. Create a source distribution of the project::

     python setup.py sdist

2. Register the project::

     python setup.py register

3. Upload the source distribution to PyPI::

     python setup.py sdist upload

4. Tag the first release of the project on GitHub with the version number from
   the ``setup.py`` file. For example if the version number in ``setup.py`` is
   0.0.1 then do::

       git tag 0.0.1
       git push --tags


----------------------------------------
Releasing a New Version of ckanext-iauth
----------------------------------------

ckanext-iauth is availabe on PyPI as https://pypi.python.org/pypi/ckanext-iauth.
To publish a new version to PyPI follow these steps:

1. Update the version number in the ``setup.py`` file.
   See `PEP 440 <http://legacy.python.org/dev/peps/pep-0440/#public-version-identifiers>`_
   for how to choose version numbers.

2. Create a source distribution of the new version::

     python setup.py sdist

3. Upload the source distribution to PyPI::

     python setup.py sdist upload

4. Tag the new release of the project on GitHub with the version number from
   the ``setup.py`` file. For example if the version number in ``setup.py`` is
   0.0.2 then do::

       git tag 0.0.2
       git push --tags
