package Net::Google::AuthSub::Once;
use strict;
use warnings;

our $VERSION = '0.1.0';

use URI;
use URI::QueryParam;

use Crypt::Random 'makerandom';
use Crypt::OpenSSL::RSA;
use File::Slurp 'read_file';
use MIME::Base64;

sub new {
    my ($klass, $options) = @_;
    my $self = bless {}, $klass;
    $self->{private_key_filename} = $options->{private_key_filename};
    return $self;
}

sub get_authorization_url {
    my ($self, $next_url) = @_;
    my $google_url = URI->new("http://www.google.com/accounts/AuthSubRequest");
    $google_url->query_param('next' => $next_url);
    $google_url->query_param('scope' => 'http://www.google.com/m8/feeds/contacts');
    $google_url->query_param('session' => 0);
    $google_url->query_param('secure'  => 1);
    return $google_url;
}

sub sign_request {
    my ($self, $request, $url, $token) = @_;

    my $nonce = makerandom(Size => 64);
    my $timestamp = time;
    my $data = "GET $url $timestamp $nonce";

    my $private_key = Crypt::OpenSSL::RSA->new_private_key(scalar read_file($self->{'private_key_filename'}));

    my $sig  = encode_base64($private_key->sign($data));

    my $auth = qq{AuthSub token="$token" sigalg="rsa-sha1" data="$data" sig="$sig"};
    $request->header('Authorization', $auth);

    return;
}

1;


=head1 NAME

Net::Google::AuthSub::Once - Make one secure authenticated request to a Google service

=head1 SYNOPSYS

    my $auth = Net::Google::AuthSub::Once->new();
    redirect_to($auth->get_authorization_url('http://example.com/your-next-url'));

    # Then after the response comes back
    
    # Make a request to the Google service
    my $auth = Net::Google::AuthSub::Once->new({ private_key_filename => 'filename' });
    my $request = HTTP::Request->new(GET => 'http://www.google.com/...');
    $auth->sign_request($request);
    my $resp = $ua->request($request);

=head1 DESCRIPTION

You must add your domain on Google for using secure requests. This module only
supports secure requests.  L<https://www.google.com/accounts/ManageDomains>

Google has some information about create the private key file you need.

L<http://code.google.com/apis/gdata/docs/auth/authsub.html#Registered>

=cut

