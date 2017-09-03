# This script generate a series of passwords containing the null
# character and the relative bcrypt hash.

use strict;
use warnings;

use Digest::SHA;
use Encode;
use Crypt::Eksblowfish::Bcrypt qw();

# This function is directly stolen from RT code, and creates a bcrypt
# hash by generating the SHA512 digest of the real password, and then
# passing the digest, in its binary format, to bcrypt.
# The first argument is the password and the second one is the salt.
sub GeneratePassword_bcrypt {
    my $password = shift;
    my $salt = shift;
    my $rounds = 10;

    my $hash = Crypt::Eksblowfish::Bcrypt::bcrypt_hash({
        key_nul => 1,
        cost    => $rounds,
        salt    => $salt,
    }, Digest::SHA::sha512( Encode::encode( 'UTF-8', $password) ) );

    return join("\$", "", "2b", sprintf("%02d", $rounds),
        Crypt::Eksblowfish::Bcrypt::en_base64( $salt ).
        Crypt::Eksblowfish::Bcrypt::en_base64( $hash )
    );
}

# Convert a string to its hexadecimal representation
sub StringToHex {
    my $string = shift;
    return unpack("H*", $string);
}

sub GeneratePasswords {
    my $salt = shift;
    
    for(my $i=0; $i<100; $i++) {
        my $pwd = sprintf("testpwd%03d", $i);
        my $hash = Digest::SHA::sha512( Encode::encode( 'UTF-8', $pwd));
        my $bcrypt_pwd = GeneratePassword_bcrypt($pwd, $salt);
        if(index($hash, "\0") != -1) {
            print sprintf("%s - %s - %s\n", $pwd, StringToHex($hash), $bcrypt_pwd);
        }
    }
}


# Create a salt for the password encryption. The salt is not changed
# between this script invocations, as it's only useful to generate
# test cases.
my $salt = "ABCDEFGHILMNOPQR";

# Find test cases with the choosen salt
GeneratePasswords($salt);
