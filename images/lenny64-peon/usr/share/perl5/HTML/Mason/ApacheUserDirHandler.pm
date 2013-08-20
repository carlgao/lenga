# -*- perl -*-

# Written by Steve Haslam.
# Updated for Apache2 by Derek W. Poon.
# All rights reserved.
# This program is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.

# HTML::Mason::ApacheUserDirHandler
#  Run as a mod_perl request handler, create
#  HTML::Mason::ApacheHandler objects on demand to handle requests,
#  keying on the username from the URI. Keep the created ApacheHandler
#  objects in a cache.

require 5;
package HTML::Mason::ApacheUserDirHandler;
use strict;
use HTML::Mason::ApacheHandler;
BEGIN {
    if (HTML::Mason::ApacheHandler::APACHE2) {
        require Apache2::Const;
        import Apache2::Const qw(DECLINED);
        require Apache2::Log;
        require Apache2::RequestUtil;
    } else {
        require Apache::Constants;
        import Apache::Constants qw(DECLINED);
        require Apache::Log;
    }
}
use vars qw(%userdir_handlers);

sub handler {
    my $r = shift;

    my $apr = HTML::Mason::ApacheHandler::APACHE2 ? $r
                                                  : Apache::Request->new($r);

    $apr->log->debug("Finding correct handler for ".$r->uri);

    if ($r->uri =~ m|^/~([a-zA-Z][a-zA-Z0-9_]*)/(.*)|) {
    my($username, $subpath) = ($1, $2);

    my $h = $userdir_handlers{$username};
    if ($h) {
        if (ref($h)) {
        $apr->log->debug("Reusing $h for user \"$username\"");
        return $h->handle_request($r);
        }
        else {
        $apr->log->debug("Skipping previously bad username \"$username\" ($h)");
        return DECLINED;
        }
    }

    $apr->log->debug("Trying to create new handler for \"$username\"");
    my ($u_name, $u_passwd, $u_uid, $u_gid, $u_quota, $u_comment, $u_gcos, $u_dir, $u_shell, $u_expire) = getpwnam($username);
    if (!$u_name) {
        $apr->log->error("User \"$username\" not found");
        $userdir_handlers{$username} = "User not found";
        return DECLINED;
    }

    if (!-d $u_dir) {
        $apr->log->error("User \"$username\" has non-existent home directory \"$u_dir\"");
        $userdir_handlers{$username} = "Home directory does not exist";
        return DECLINED;
    }

    my $comp_root = "$u_dir/public_html";
    if (!-d $comp_root) {
        $apr->log->error("User \"$username\": proposed component root $comp_root does not exist");
        $userdir_handlers{$username} = "Proposed component root does not exist";
        return DECLINED;
    }

    eval {
        my $spooldir = $r->dir_config('XMasonSpoolDir') || "/var/cache/mason";
        my $spoolname = $username; # Vet $username here if we expand the regex to match it above
        my @args_method = defined $r->dir_config('MasonArgsMethod') ?
            (args_method => $r->dir_config('MasonArgsMethod')) : ();
        $h = HTML::Mason::ApacheHandler->new(data_dir => "$spooldir/$spoolname",
                         comp_root => $comp_root,
                         apache_status_title => "HTML::Mason status (for $username)",
                         in_package => "HTML::Mason::UserDirCommands::$username",
                         @args_method);
    };
    if ($@) {
        my $err = $@;
        $apr->log->error("Failed to create Mason handler object: $err");
        $userdir_handlers{$username} = $err;
        return DECLINED;
    }

    $apr->log->debug("New handler created as $h, chaining request");
    $userdir_handlers{$username} = $h;
    return $h->handle_request($r);
    }
    else {
    $apr->log->debug("$r->uri does not look like a userdir URI, declining");
    return DECLINED;
    }
}

__END__
