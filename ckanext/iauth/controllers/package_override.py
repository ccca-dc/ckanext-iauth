import paste.fileapp
import mimetypes
import logging
import ckan.model as model
import ckan.logic as logic
import pylons.config as config
import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.plugins as p
from ckan.common import request, c, g, response
import ckan.lib.uploader as uploader
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.lib.dictization as dictization
from pylons.i18n.translation import _, ungettext
import ckan.lib.i18n as i18n
from ckan.controllers.package import PackageController
import ckan.lib.navl.dictization_functions as dict_fns
import ckan.authz as authz


from urlparse import urlparse
from posixpath import basename, dirname

render = base.render
abort = base.abort
redirect = base.redirect

NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized
ValidationError = logic.ValidationError
check_access = logic.check_access
get_action = logic.get_action
tuplize_dict = logic.tuplize_dict
clean_dict = logic.clean_dict
parse_params = logic.parse_params

log = logging.getLogger(__name__)


class PackageContributeOverride(p.SingletonPlugin, PackageController):
    # Restrict download from resource to registered user
    def resource_download(self, id, resource_id, filename=None):
        """
        Provides a direct download by either redirecting the user to the url
        stored or downloading an uploaded file directly.
        """
        context = {'model': model, 'session': model.Session,
                   'user': c.user, 'auth_user_obj': c.userobj}

        try:
            rsc = get_action('resource_show')(context, {'id': resource_id})
            get_action('package_show')(context, {'id': id})
            print rsc['anonDownload']
        except (NotFound, NotAuthorized):
            abort(404, _('Resource not found'))

        if authz.auth_is_anon_user(context) and rsc['anonDownload'] == 'false':
            abort(401, _('Unauthorized to read resource %s') % id)
        else:
            if rsc.get('url_type') == 'upload':
                upload = uploader.ResourceUpload(rsc)
                filepath = upload.get_path(rsc['id'])
                fileapp = paste.fileapp.FileApp(filepath)
                try:
                    status, headers, app_iter = request.call_application(fileapp)
                except OSError:
                    abort(404, _('Resource data not found'))
                response.headers.update(dict(headers))
                content_type, content_enc = mimetypes.guess_type(
                    rsc.get('url', ''))
                if content_type:
                    response.headers['Content-Type'] = content_type
                response.status = status
                return app_iter
            elif not 'url' in rsc:
                abort(404, _('No download is available'))
            redirect(rsc['url'])
