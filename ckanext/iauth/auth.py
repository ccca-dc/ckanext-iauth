from ckan.logic import auth_allow_anonymous_access

import ckan.logic as logic
import ckan.authz as authz
import ckan.plugins.toolkit as toolkit
from ckan.logic.auth import get_resource_object
from ckan.lib.base import _
import ckan.plugins as p
from ckan.logic.auth.create import _check_group_auth
import ckan.logic.auth as logic_auth

from pylons import config

from ckanext.iauth.action import check_loaded_plugin

#For editor_mod
last_session = ""
last_access = False


@logic.auth_allow_anonymous_access
def package_update(context, data_dict):

    #print "***************** Anja package_update iauth"

    package = logic_auth.get_package_object(context, data_dict)

    # Handle
    if check_loaded_plugin (context, {'name':'handle'}):
        if package.private is not None and package.private is False and data_dict is not None and data_dict.get('private', '') == 'True':
            return {'success': False,
                    'msg': 'Public datasets cannot be set private again'}

    #Thredds - subset
    if check_loaded_plugin (context, {'name':'thredds'}):
        from ckanext.thredds import helpers
        if package.private is not None and package.private is True and data_dict is not None and data_dict.get('private', '') == 'False':
            subset_uniqueness = helpers.check_subset_uniqueness(package.id)

            if len(subset_uniqueness) > 0:
                return {'success': False,
                        'msg': 'Dataset cannot be set public as it contains a subset, which was already published'}

    # Editor_mod
    editor_restricted = False
    if 'ckanext.iauth.editor_modified' in config:
        #print "Hello Moonlight"
        editor_mod = config.get('ckanext.iauth.editor_modified')
        if editor_mod == 'true' or editor_mod == 'True':
           editor_restricted = True


    user_info = context['auth_user_obj'] ## Check if logged in :-)

    #print user_info

    if editor_restricted and user_info:
        #print "Hallo 1"
        global last_session
        global last_access

        s = context['session'] # always exists

        try:
            my_package = context['package'] # not on resources or page reload
            owner_org =  my_package.owner_org
            #print owner_org
        except: # per resource: session; and on page reload: only session
            if s == last_session:
                if last_access:
                    return {'success': True}
                else:
                    return {'success': False, 'msg': 'You are only allowed to edit your own datasets'}
            else:
                #print "internal problem"
                return {'success': False, 'msg': 'Access denied'} # We should not run into this path :-)


        # SAVE session - for the follwing resources that pass through this function and for page relaods
        last_session = context['session']
        #print last_session

        #check if ADMIN
        user_info = context['auth_user_obj']
        #print context

        org_list = toolkit.get_action('organization_list_for_user')({}, {"id": user_info.id, "permission": "member_create"})
        #print "Hello2"
        #print org_list
        for x in org_list:
            #print x.values()
            if owner_org in x.values():
                    #print "success"
                    #print last_session
                    last_access = True
                    return {'success': True}

        # Editors only allowed to edit own packages
        if user_info.id == my_package.creator_user_id or user_info.email == my_package.maintainer_email or user_info.email == my_package.author_email:
            last_access = True
            return {'success': True}
        else:
            last_access = False
            return {'success': False, 'msg': 'You are only allowed to edit your own datasets'}

    #print "Hallo 2"

    # From Core CKAN
    user = context.get('user')
    package = logic_auth.get_package_object(context, data_dict)

    if package.owner_org:
        # if there is an owner org then we must have update_dataset
        # permission for that organization
        check1 = authz.has_user_permission_for_group_or_org(
            package.owner_org, user, 'update_dataset'
        )
    else:
        # If dataset is not owned then we can edit if config permissions allow
        if authz.auth_is_anon_user(context):
            check1 = all(authz.check_config_permission(p) for p in (
                'anon_create_dataset',
                'create_dataset_if_not_in_organization',
                'create_unowned_dataset',
                ))
        else:
            check1 = all(authz.check_config_permission(p) for p in (
                'create_dataset_if_not_in_organization',
                'create_unowned_dataset',
                )) or authz.has_user_permission_for_some_org(
                user, 'create_dataset')
    if not check1:
        return {'success': False,
                'msg': _('User %s not authorized to edit package %s') %
                        (str(user), package.id)}
    else:
        check2 = _check_group_auth(context, data_dict)
        if not check2:
            return {'success': False,
                    'msg': _('User %s not authorized to edit these groups') %
                            (str(user))}

    return {'success': True}
    # From Core CKAN END



def resource_update(context, data_dict):

    resource = logic_auth.get_resource_object(context, data_dict)

    #resourceversions
    if check_loaded_plugin (context, {'name':'resourceversions'}):

        upload = False
        if 'upload' in data_dict and data_dict['upload'] != "" or 'upload_local' in data_dict and data_dict['upload_local'] != "" or 'upload_remote' in data_dict and data_dict['upload_remote'] != "":
            upload = True

        if upload or 'url' in data_dict and "/" in data_dict['url'] and data_dict['url'] != resource.url:
            # check if resource has a newer version
            if 'newer_version' in resource.extras and resource.extras['newer_version'] != "":
                return {'success': False, 'msg': 'Older versions cannot be updated'}
            # check if this is a subset, then it cannot create a new version like that

            if check_loaded_plugin (context, {'name':'thredds'}):
                if 'subset_of' in resource.extras and resource.extras['subset_of'] != "":
                    return {'success': False, 'msg': 'Please create only new versions from the original resource'}

    # From Core
    model = context['model']
    user = context.get('user')
    #resource = logic_auth.get_resource_object(context, data_dict)

    # check authentication against package
    pkg = model.Package.get(resource.package_id)
    if not pkg:
        raise logic.NotFound(
            _('No package found for this resource, cannot check auth.')
        )

    pkg_dict = {'id': pkg.id}
    authorized = authz.is_authorized('package_update', context, pkg_dict).get('success')

    if not authorized:
        return {'success': False,
                'msg': _('User %s not authorized to edit resource %s') %
                        (str(user), resource.id)}
    else:
        return {'success': True}
    # From Core END

def package_delete(context, data_dict):

    package = toolkit.get_action('package_show')(data_dict={'id': data_dict['id']})

    # Handle
    if check_loaded_plugin (context, {'name':'handle'}):
        # check if package is public
        if package['private'] is False:
            return {'success': False, 'msg': 'Public datasets cannot be deleted'}

    # From CORE
    # Defer authorization for package_delete to package_update, as deletions
    # are essentially changing the state field
    #return _auth_update.package_update(context, data_dict)
    # From CORE END

    #Renamed ...
    return authz.is_authorized('package_update', context, data_dict)




def resource_delete(context, data_dict):

    # Handle
    if check_loaded_plugin (context, {'name':'handle'}):

        resource = get_resource_object(context, data_dict)

        # check authentication against package
        pkg = model.Package.get(resource.package_id)

        if not pkg:
            raise logic.NotFound(_('No package found for this resource, cannot check auth.'))

        # check if package is public
        if pkg['private'] is False:
            return {'success': False, 'msg': 'Public resources cannot be deleted'}

    # From CORE
    model = context['model']
    user = context.get('user')
    resource = get_resource_object(context, data_dict)

    # check authentication against package
    pkg = model.Package.get(resource.package_id)
    if not pkg:
        raise logic.NotFound(_('No package found for this resource, cannot check auth.'))

    pkg_dict = {'id': pkg.id}
    authorized = package_delete(context, pkg_dict).get('success')

    if not authorized:
        return {'success': False, 'msg': _('User %s not authorized to delete resource %s') % (user, resource.id)}
    else:
        return {'success': True}
    # From CORE End
