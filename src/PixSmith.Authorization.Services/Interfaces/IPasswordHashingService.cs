using System;
using System.Collections.Generic;
using System.Text;

namespace PixSmith.Authorization.Services.Interfaces
{
	public interface IPasswordHashingService
	{
		string HashPassword(string plaintext);
		bool VerifyPassword(string plaintext, string hash);
	}
}
