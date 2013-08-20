# NOTE: Derived from blib/lib/CGI/XMLForm/Path.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package CGI::XMLForm::Path;

#line 102 "blib/lib/CGI/XMLForm/Path.pm (autosplit into blib/lib/auto/CGI/XMLForm/Path/isChildPath.al)"
sub isChildPath {
	my $self = shift;
	my $compare = shift;

	# Now compare each level of the tree, and throw away attributes.
	my @a = @{$self->{_fullpath}};
	my @b = @{$compare->{_fullpath}};

	if (@a >= @b) {
		return 0;
	}
	foreach ($#a..0) {
		$a[$_] =~ s/\[.*\]//;
		$b[$_] =~ s/\[.*\]//;
		return 0 if ($a[$_] ne $b[$_]);
	}
	return 1;
}

# end of CGI::XMLForm::Path::isChildPath
1;
