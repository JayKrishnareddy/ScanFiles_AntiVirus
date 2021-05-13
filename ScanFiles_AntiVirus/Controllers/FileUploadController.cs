using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using nClam;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace ScanFiles_AntiVirus.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class FileUploadController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        public FileUploadController(
            IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]  
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Content("file not selected");

            var ms = new MemoryStream();
            file.OpenReadStream().CopyTo(ms);
            byte[] fileBytes = ms.ToArray();
            string Result = string.Empty;
            try
            {
                // Scan with Docker image
                var clam = new ClamClient(this._configuration["ClamAVServer:URL"],
                Convert.ToInt32(this._configuration["ClamAVServer:Port"]));

                // Scan with Clam Av server
                //var clam = new ClamClient(IPAddress.Parse("127.0.0.1"), 3310);
                var scanResult = await clam.SendAndScanFileAsync(fileBytes);

                // Switch Expression C# 8.0 
                Result =  scanResult.Result switch
                {
                    ClamScanResults.Clean => "Clean",
                    ClamScanResults.VirusDetected => "Virus Detected",
                    ClamScanResults.Error => "Error in File",
                    ClamScanResults.Unknown => "Unknown File",
                          _ => "No case available"
                };
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return Ok(Result);
        }
    }
}
