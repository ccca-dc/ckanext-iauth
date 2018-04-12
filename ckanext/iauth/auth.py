from ckan.logic import auth_allow_anonymous_access

import ckan.logic as logic
import ckan.authz as authz
import ckan.plugins.toolkit as toolkit
from ckan.logic.auth import get_resource_object
from ckan.logic.auth.create import _group_or_org_member_create
from ckan.lib.base import _
import ckan.plugins as p
import ckan.logic.auth as logic_auth

from pylons import config

from ckanext.iauth.action import check_loaded_plugin

from ckan.logic.auth import (get_package_object, get_resource_object, get_group_object)

from ckanext.thredds import helpers as helpers_thredds
from ckanext.resourceversions import helpers as helpers_resourceversions

_check_access = logic.check_access

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
        try:
            user_info = toolkit.get_action('user_show')({}, {'id': user})
        except:
            authorized = False

        #Editors and Members left
        if authorized:  # check if we need to restrict access
            if user_info['id'] != package.creator_user_id and user_info['email'] != package.maintainer_email and user_info['email'] != package.author_email:
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


@logic.auth_allow_anonymous_access
def package_create(context, data_dict=None):
    user = context['user']

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
        return {'success': False, 'msg': _('User %s not authorized to create packages') % user}

    check2 = _check_group_auth(context,data_dict)
    if not check2:
        return {'success': False, 'msg': _('User %s not authorized to edit these groups') % user}

    # If an organization is given are we able to add a dataset to it?
    data_dict = data_dict or {}
    org_id = data_dict.get('owner_org')
    if org_id and not authz.has_user_permission_for_group_or_org(
            org_id, user, 'create_dataset'):
        return {'success': False, 'msg': _('User %s not authorized to add dataset to this organization') % user}
    return {'success': True}


#@logic.auth_allow_anonymous_access
def package_update(context, data_dict):

    package = logic_auth.get_package_object(context, data_dict)
    # Handle
    if check_loaded_plugin (context, {'name':'handle'}):
        if package.private is not None and package.private is False and data_dict is not None and data_dict.get('private', '') == 'True':
            return {'success': False,
                    'msg': 'Public datasets cannot be set private again'}

    # Thredds - subset
    if check_loaded_plugin(context, {'name': 'thredds'}):
        if package.private is not None and package.private is True and data_dict is not None and data_dict.get('private', '') == 'False':
            subset_uniqueness = helpers_thredds.check_subset_uniqueness(package.id)

            if len(subset_uniqueness) > 0:
                return {'success': False,
                        'msg': 'Dataset cannot be set public as it contains a subset, which was already published'}
    # check Admin
    user = context.get('user')
    authorized_admin = authz.has_user_permission_for_group_or_org(package.owner_org, user, 'member_create')

    if authorized_admin:
        group_check = _check_group_auth(context, data_dict)
        if not group_check:
            return {'success': False,
                    'msg': _('User %s not authorized to edit these groups') %
                            (str(user))}
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

def _check_group_auth(context, data_dict):
    '''Has this user got update permission for all of the given groups?
    If there is a package in the context then ignore that package's groups.
    (owner_org is checked elsewhere.)
    :returns: False if not allowed to update one (or more) of the given groups.
              True otherwise. i.e. True is the default. A blank data_dict
              mentions no groups, so it returns True.

    '''
    # fixed function from original code, see below
    if not data_dict:
        return True

    model = context['model']
    user = context['user']
    pkg = context.get("package")

    api_version = context.get('api_version') or '1'

    group_blobs = data_dict.get('groups', [])
    groups = set()
    for group_blob in group_blobs:
        # group_blob might be a dict or a group_ref
        if isinstance(group_blob, dict):
            if api_version == '1':
                id = group_blob.get('name')
            else:
                id = group_blob.get('id')
            if not id:
                continue
        else:
            id = group_blob
        grp = model.Group.get(id)
        if grp is None:
            raise logic.NotFound(_('Group was not found.'))
        groups.add(grp)

    if pkg:
        pkg_groups = pkg.get_groups()

        groups = groups - set(pkg_groups)

    for group in groups:
        # users should be able to add datasets to an addition_without_group_membership group, therefore they need to be added as a member
        group_with_extras = toolkit.get_action('group_show')(context, {'id': group.id})
        user_to_add = toolkit.get_action('user_show')(context, {'id': user})
        member_list = toolkit.get_action('member_list')(context, {'id': group.id})

        if group_with_extras.get('addition_without_group_membership', 'False') == 'True' and not any(member[0] == user_to_add['id'] for member in member_list):
            toolkit.get_action('member_create')(context, {'object_type': 'user', 'object': user, 'capacity': u'member', 'id': group.id})

        # in the original code the permission was 'update', however update is not a valid permission for member (only 'read' and 'manage_group')
        if not authz.has_user_permission_for_group_or_org(group.id, user, 'manage_group'):
            return False

    return True


#@logic.auth_allow_anonymous_access
def resource_update(context, data_dict):

    resource = logic_auth.get_resource_object(context, data_dict)
    #print(resource)
    pkg = toolkit.get_action('package_show')(context, {'id': resource.package_id})

    # resourceversions
    if check_loaded_plugin(context, {'name': 'resourceversions'}):
        try:
            newer_versions = [element['id'] for element in pkg['relations'] if element['relation'] == 'has_version']
        except:
            newer_versions = []

        if len(newer_versions) > 0:
            upload = False
            if data_dict.get('upload', '') != "" or data_dict.get('upload_local', '') != "" or data_dict.get('upload_remote', '') != "":
                upload = True

            if context.get('create_version', True) is True and pkg['private'] is False:
                if (upload is True
                or data_dict.get('clear_upload') not in ("", None) and data_dict['url'] != resource.url
                or (data_dict.get('clear_upload') in ("", None) and data_dict['url'] != resource.url and resource.url_type in ("", None))):
                    # check if resource has a newer version
                    errors = {'url': [u'Older versions cannot be updated']}
                    raise ValidationError(errors)
                    return {'success': False, 'msg': 'Older versions cannot be updated'}

    # Thredds - subset
    if check_loaded_plugin(context, {'name': 'thredds'}):
        if helpers_thredds.get_parent_dataset(pkg['id']) is not None:
            if 'for_view' not in context:
                return {'success': False,
                        'msg': _('Subsets cannot be modified')}

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
    model = context['model']
    user = context.get('user')
    resource = get_resource_object(context, data_dict)

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

    # check authentication against package
    pkg = model.Package.get(resource.package_id)
    if not pkg:
        raise logic.NotFound(_('No package found for this resource, cannot check auth.'))
    # From CORE End

    # resourceversions
    if check_loaded_plugin(context, {'name': 'resourceversions'}):
        versions = helpers_resourceversions.get_versions(pkg['id'])

        if len(versions) > 0:
            return {'success': False, 'msg': 'Resource versions cannot be deleted. Please delete whole package.'}

    # Thredds - subset
    if check_loaded_plugin(context, {'name': 'thredds'}):
        if helpers_thredds.get_parent_dataset(resource['package_id']) is not None:
            return {'success': False,
                    'msg': _('Resource subsets cannot be deleted. Please delete whole package.')}

    # From CORE
    pkg_dict = {'id': pkg.id}
    authorized = package_delete(context, pkg_dict).get('success')

    if not authorized:
        return {'success': False, 'msg': _('User %s not authorized to delete resource %s') % (user, resource.id)}
    else:
        return {'success': True}
    # From CORE End


def member_create(context, data_dict):
    group = logic_auth.get_group_object(context, data_dict)
    user = context['user']

    # users should be able to add themselves as member to an "addition_without_group_membership" group
    # and they should be able to add packages even if they aren't members
    if not group.is_organization:
        group_with_extras = toolkit.get_action('group_show')(context, {'id': data_dict['id']})

        if group_with_extras.get('addition_without_group_membership', 'False') == 'True':
            if data_dict['object_type'] == "user" and data_dict.get('capacity') == "member":
                user_to_add = toolkit.get_action('user_show')(context, {'id': data_dict['object']})

                if user_to_add['name'] == user:
                    return {'success': True}
            elif data_dict['object_type'] == "package" and _check_access('package_update', context, {'id': data_dict['object']}):
                return {'success': True}

    # User must be able to update the group to add a member to it
    permission = 'update'
    # However if the user is member of group then they can add/remove datasets
    if not group.is_organization and data_dict.get('object_type') == 'package':
        permission = 'manage_group'

    authorized = authz.has_user_permission_for_group_or_org(group.id,
                                                                user,
                                                                permission)
    if not authorized:
        return {'success': False,
                'msg': _('User %s not authorized to edit group %s') %
                        (str(user), group.id)}
    else:
        return {'success': True}


def member_delete(context, data_dict):
    return authz.is_authorized('member_create', context, data_dict)
