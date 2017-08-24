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

from ckan.logic.auth import (get_package_object, get_resource_object, get_group_object,get_related_object)


ValidationError = logic.ValidationError
NotAuthorized = toolkit.NotAuthorized
Invalid = toolkit.Invalid

def _check_unauthorized_upload(context, data_dict, owner_org):
    # Return True if UNAUTHORIZED and False if authorized

    special_org_name = ''

    if 'ckanext.iauth.special_org' in config:
        special_org_name = config.get ('ckanext.iauth.special_org')
    else:
        return False

    group_dict = logic.get_action('organization_show')(context, {'id': owner_org})

    if group_dict and 'name' in group_dict:
        if group_dict['name'] !=  special_org_name:
            return False

    if ('upload_local' in data_dict and data_dict['upload_local'] != '')  or ('upload_remote' in data_dict and data_dict['upload_remote'] != '') :
            return True

    return False

def resource_create(context, data_dict):

    #################################################################
    ### From CKAN Core
    model = context['model']
    user = context.get('user')
    package_id = data_dict.get('package_id')
    if not package_id and data_dict.get('id'):
        # This can happen when auth is deferred, eg from `resource_view_create`
        resource = logic_auth.get_resource_object(context, data_dict)
        package_id = resource.package_id

    if not package_id:
        raise logic.NotFound(
            _('No dataset id provided, cannot check auth.')
        )

    # check authentication against package
    pkg = model.Package.get(package_id)
    if not pkg:
        raise logic.NotFound(
            _('No package found for this resource, cannot check auth.')
        )

    pkg_dict = {'id': pkg.id}
    authorized = authz.is_authorized('package_update', context, pkg_dict).get('success')

    ######## Modification for special_org, Anja, 18.8.17
    # check unauthrized upload for memebers of special_org
    if  _check_unauthorized_upload(context, data_dict, pkg.owner_org):
        errors = { 'url': [u'Members of CCCA Extern are not authorized to upload resources']}
        data_dict['upload_local'] = ''
        data_dict['upload_remote'] = ''
        # We need to delete the field, because localimp validator only requires "non-empty"
        # and user can just press again "add" or "update"
        if 'url' in data_dict:
            data_dict['url'] = ''
        raise ValidationError(errors)
    ######## End Modification for special_org, Anja, 18.8.17

    if not authorized:
        return {'success': False,
                'msg': _('User %s not authorized to create resources on dataset %s') %
                        (str(user), package_id)}
    else:
        return {'success': True}
    ### From CKAN Core END
    #################################################################


@logic.auth_allow_anonymous_access
def package_show(context, data_dict):
    #########################################################
    # From Core CKAN ----
    user = context.get('user')
    package = get_package_object(context, data_dict)
    # draft state indicates package is still in the creation process
    # so we need to check we have creation rights.
    if package.state.startswith('draft'):
        auth = authz.is_authorized('package_update',
                                       context, data_dict)
        authorized = auth.get('success')
    # new elif Anja, 17.8.17; let otherwise to problems with create_subset
    elif package.state.startswith('deleted'):
        return {'success': True}
    elif package.owner_org is None and package.state == 'active':
        return {'success': True}
    else:
        # anyone can see a public package
        if not package.private and package.state == 'active':
            return {'success': True}
        authorized = authz.has_user_permission_for_group_or_org(
            package.owner_org, user, 'read')

    ####################### Modification ###########################
    # Every normal (Editor) user is only allowed to see his own private packages
    if package.private and authorized:

        # check Admin
        authorized_admin = authz.has_user_permission_for_group_or_org(package.owner_org, user, 'member_create')

        if  authorized_admin:
            return {'success': True}

        # Editor remains; check if we try to edit our own dataset
        user_info = context.get('auth_user_obj')

        if user_info == None:  # Anon User - should not happen here
            authorized = False

        #Editors and Members left
        if authorized:  # check if we need to restrict access
            if user_info.id != package.creator_user_id and  user_info.email != package.maintainer_email and user_info.email != package.author_email:
                #errors = { 'private': [u'Not authorized to to see private datasets']}

                # Leider geht das hier alles nicht :-(
                #raise Exception("TEst")
                #raise NotAuthorized("Test")
                #raise ValidationError("Test")


                authorized = False

    ####################### Modification END ###########################

    if not authorized:
        return {'success': False, 'msg': _('User %s not authorized to read package %s') % (user, package.id)}
    else:
        return {'success': True}

    # From Core CKAN ----  END
    ###############################################################


#@logic.auth_allow_anonymous_access
def package_update(context, data_dict):

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
    # check Admin
    user = context.get('user')
    authorized_admin = authz.has_user_permission_for_group_or_org(package.owner_org, user, 'member_create')

    if  authorized_admin:
        return {'success': True}

    # Editor_mod
    editor_restricted = False
    if 'ckanext.iauth.editor_modified' in config:
        editor_mod = config.get('ckanext.iauth.editor_modified')
        if editor_mod == 'true' or editor_mod == 'True':
           editor_restricted = True

    # From Core CKAN ---- # Modified for Restricted Editor - editor_mod
    user = context.get('user')
    package = logic_auth.get_package_object(context, data_dict)

    if package.owner_org:
        # if there is an owner org then we must have update_dataset
        # permission for that organization
        check1 = authz.has_user_permission_for_group_or_org(
            package.owner_org, user, 'update_dataset'
        )
        ########################################################################
        #### Modification for restricted editor: editor_mod flag - Anja 13.7.17
        if check1 and editor_restricted:

            user_info = context.get('auth_user_obj')

            #check if we are an Organisation Admin - sysadmins do not come into this function at all!!
            owner_org = package.owner_org
            local_access = False
            org_list = toolkit.get_action('organization_list_for_user')({}, {"id": user_info.id, "permission": "member_create"})
            for x in org_list:
                if owner_org in x.values():
                    local_access = True

            if not local_access:   # We are Editor: restrict access
                # Editors only allowed to edit own packages
                if user_info.id == package.creator_user_id or user_info.email == package.maintainer_email or user_info.email == package.author_email:
                    check1 = True
                else:
                    check1 = False

        #### Modification for restricted editor: editor_mod flag - Anja 13.7.17 END
        ###########################################################################
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


#@logic.auth_allow_anonymous_access
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
        #return {'success': True}

        ######## Modification for special_org, Anja, 18.8.17
        # check unauthorized upload for members of special_org
        if  _check_unauthorized_upload(context, data_dict, pkg.owner_org):
            errors = { 'url': [u'Members of CCCA Extern are not authorized to upload resources']}
            data_dict['upload_local'] = ''
            data_dict['upload_remote'] = ''
            # We need to delete the field, because localimp validator only requires "non-empty"
            # and user can just press again "add" or "update"
            if 'url' in data_dict:
                data_dict['url'] = ''
            raise ValidationError(errors)
            return {'success': False,
                    'msg': _('Members of CCCA Extern are not authorized to upload resources')}

        ######## End Modification for special_org, Anja, 18.8.17

        return {'success': True}
    # From Core END

#@logic.auth_allow_anonymous_access
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

#@logic.auth_allow_anonymous_access
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
