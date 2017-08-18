import re
import datetime
import pytz

from pylons import config
from pylons.i18n import gettext

import ckan.logic as logic
get_action = logic.get_action

import  ckan.plugins.toolkit as tk
context = tk.c
import ckan.lib.base as base
Base_c = base.c
from pylons import c
import logging
log = logging.getLogger(__name__)
import ckan.lib.helpers as h


def iauth_get_special_org ():

    if 'ckanext.iauth.special_org' in config:
        return config.get ('ckanext.iauth.special_org')
    else:
        return ''

def iauth_check_controller (context):

    try:
        if context.controller == 'organization':
            return True

    except:
        return False

    return False

def iauth_check_admin(context, userobj):

    if not userobj:
        return False
    try:
        if context.controller == 'organization':
            if userobj.id in context.group_admins:
                    return True
    except:
       return False
    return False
