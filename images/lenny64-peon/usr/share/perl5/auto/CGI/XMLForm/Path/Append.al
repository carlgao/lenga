# NOTE: Derived from blib/lib/CGI/XMLForm/Path.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package CGI::XMLForm::Path;

#line 148 "blib/lib/CGI/XMLForm/Path.pm (autosplit into blib/lib/auto/CGI/XMLForm/Path/Append.al)"
sub Append {
	my $self = shift;
	my $element = shift;
	my %attribs = @_;
	if (%attribs) {
		$element .= "[";

		$element .= join " and ",
					(map "\@$_=\"$attribs{$_}\"", (keys %attribs));
		$element .= "]";
	}
	push @{$self->{_fullpath}}, $element;
	push @{$self->{Parts}}, $element;
	$self->{_path} .= "/". $element;
}

# end of CGI::XMLForm::Path::Append
1;
