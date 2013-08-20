# NOTE: Derived from blib/lib/CGI/XMLForm/Path.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package CGI::XMLForm::Path;

#line 89 "blib/lib/CGI/XMLForm/Path.pm (autosplit into blib/lib/auto/CGI/XMLForm/Path/rebuildSelf.al)"
sub rebuildSelf {
	my $self = shift;
	$self->buildSelf(new CGI::XMLExt::Path);
}

# end of CGI::XMLForm::Path::rebuildSelf
1;
