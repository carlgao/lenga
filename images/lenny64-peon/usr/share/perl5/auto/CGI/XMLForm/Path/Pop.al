# NOTE: Derived from blib/lib/CGI/XMLForm/Path.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package CGI::XMLForm::Path;

#line 164 "blib/lib/CGI/XMLForm/Path.pm (autosplit into blib/lib/auto/CGI/XMLForm/Path/Pop.al)"
sub Pop {
	my $self = shift;
	pop @{$self->{_fullpath}};
	$self->{_path} =~ s/^(.*)\/.*?$/$1/;
	pop @{$self->{Parts}};
}

# end of CGI::XMLForm::Path::Pop
1;
