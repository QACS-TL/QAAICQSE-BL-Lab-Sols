using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace UserManagementSystem
{
    public class UserManager
    {
        private readonly Dictionary<Guid, UserRecord> _usersById = new();
        private readonly Dictionary<string, Guid> _userIdsByEmail = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _syncRoot = new();

        public string RegisterUser(string email, string password, string personalInfo)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            {
                return "User registration rejected: email and password are required.";
            }

            lock (_syncRoot)
            {
                if (_userIdsByEmail.ContainsKey(email))
                {
                    return "User registration rejected: email is already in use.";
                }

                byte[] salt = RandomNumberGenerator.GetBytes(16);
                byte[] hash = HashPassword(password, salt);
                Guid userId = Guid.NewGuid();
                string resetToken = Guid.NewGuid().ToString("N");

                var user = new UserRecord
                {
                    UserId = userId,
                    Email = email.Trim(),
                    Salt = salt,
                    PasswordHash = hash,
                    ResetToken = resetToken,
                    ProfileData = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["personalInfo"] = personalInfo ?? string.Empty
                    }
                };

                _usersById[userId] = user;
                _userIdsByEmail[user.Email] = userId;

                return $"User registration confirmed. UserId: {userId}";
            }
        }

        public bool AuthenticateUser(string email, string password)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            {
                return false;
            }

            lock (_syncRoot)
            {
                if (!_userIdsByEmail.TryGetValue(email, out Guid userId) || !_usersById.TryGetValue(userId, out UserRecord? user))
                {
                    return false;
                }

                return VerifyPassword(password, user.Salt, user.PasswordHash);
            }
        }

        public bool ResetPassword(string email, string newPassword, string resetToken)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(newPassword) || string.IsNullOrWhiteSpace(resetToken))
            {
                return false;
            }

            lock (_syncRoot)
            {
                if (!_userIdsByEmail.TryGetValue(email, out Guid userId) || !_usersById.TryGetValue(userId, out UserRecord? user))
                {
                    return false;
                }

                if (!string.Equals(user.ResetToken, resetToken, StringComparison.Ordinal))
                {
                    return false;
                }

                user.Salt = RandomNumberGenerator.GetBytes(16);
                user.PasswordHash = HashPassword(newPassword, user.Salt);
                user.ResetToken = Guid.NewGuid().ToString("N");

                return true;
            }
        }

        public string UpdateProfile(Guid userId, Dictionary<string, string> profileData)
        {
            if (profileData is null)
            {
                return "Profile update rejected: profile data is required.";
            }

            lock (_syncRoot)
            {
                if (!_usersById.TryGetValue(userId, out UserRecord? user))
                {
                    return "Profile update rejected: user not found.";
                }

                foreach (var item in profileData.Where(kvp => !string.IsNullOrWhiteSpace(kvp.Key)))
                {
                    user.ProfileData[item.Key] = item.Value ?? string.Empty;
                }

                return "Profile update confirmed.";
            }
        }

        public string DeleteUser(Guid userId, string confirmPassword)
        {
            if (string.IsNullOrWhiteSpace(confirmPassword))
            {
                return "User deletion rejected: confirmation password is required.";
            }

            lock (_syncRoot)
            {
                if (!_usersById.TryGetValue(userId, out UserRecord? user))
                {
                    return "User deletion rejected: user not found.";
                }

                if (!VerifyPassword(confirmPassword, user.Salt, user.PasswordHash))
                {
                    return "User deletion rejected: password confirmation failed.";
                }

                _usersById.Remove(userId);
                _userIdsByEmail.Remove(user.Email);
                return "User deletion confirmed.";
            }
        }

        public Dictionary<string, string>? GetUserData(Guid userId, Guid requestingUserId)
        {
            if (userId != requestingUserId)
            {
                return null;
            }

            lock (_syncRoot)
            {
                if (!_usersById.TryGetValue(userId, out UserRecord? user))
                {
                    return null;
                }

                var result = new Dictionary<string, string>(user.ProfileData, StringComparer.OrdinalIgnoreCase)
                {
                    ["userId"] = user.UserId.ToString(),
                    ["email"] = user.Email
                };

                return result;
            }
        }

        private static byte[] HashPassword(string password, byte[] salt)
        {
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
        }

        private static bool VerifyPassword(string password, byte[] salt, byte[] expectedHash)
        {
            byte[] computedHash = HashPassword(password, salt);
            return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
        }

        private sealed class UserRecord
        {
            public Guid UserId { get; init; }

            public string Email { get; init; } = string.Empty;

            public byte[] Salt { get; set; } = Array.Empty<byte>();

            public byte[] PasswordHash { get; set; } = Array.Empty<byte>();

            public string ResetToken { get; set; } = string.Empty;

            public Dictionary<string, string> ProfileData { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        }
    }
}
