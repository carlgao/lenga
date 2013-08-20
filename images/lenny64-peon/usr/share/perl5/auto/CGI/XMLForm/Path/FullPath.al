# NOTE: Derived from blib/lib/CGI/XMLForm/Path.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package CGI::XMLForm::Path;

#line 175 "blib/lib/CGI/XMLForm/Path.pm (autosplit into blib/lib/auto/CGI/XMLForm/Path/FullPath.al)"
sub FullPath {
	my $self = shift;
	my $path = "/" . (join "/", @{$self->{_fullpath}});
	$path .= ($self->Attrib ? "/\@" . $self->Attrib : '');
	$path;
}

1;
1;
# end of CGI::XMLForm::Path::FullPath
